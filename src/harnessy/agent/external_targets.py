from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import shlex
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Awaitable, Callable

from harnessy.core.workspace import ExternalTarget, WorkspaceStore
from harnessy.core.target_credentials import TargetCredentialStore


class ExternalTargetError(RuntimeError):
    pass


# This is a best-effort command policy, never an OS isolation boundary. A root
# SSH target gives every allowed target command root privileges on that host.
_BLOCKED_COMMAND_RE = re.compile(
    r"(?:^|[\s;&|()])(?:sudo|su|doas|pkexec|systemctl|service|apt(?:-get)?|dpkg|dnf|yum|rpm|apk|pacman|"
    r"mount|umount|fdisk|sfdisk|parted|mkfs(?:\.[A-Za-z0-9_-]+)?|dd|reboot|shutdown|halt|poweroff|"
    r"iptables|ip6tables|nft|pfctl|useradd|userdel|usermod|groupadd|groupdel|passwd|chroot|nsenter|"
    r"ssh|scp|sftp|telnet|nc|netcat|socat|nmap)(?:\s|$)",
    re.IGNORECASE,
)
_BLOCKED_PATH_RE = re.compile(
    r"(?:^|[\s'\"=:(])/(?:etc|root|boot|sys|proc|run|var/lib|var/run|home)(?:/|\b)",
    re.IGNORECASE,
)


@dataclass(slots=True)
class TargetCommandResult:
    ok: bool
    returncode: int | None
    stdout: str
    stderr: str
    duration_seconds: float


class ExternalTargetBroker:
    def __init__(self, workspace: WorkspaceStore, *, chat_id: str = '') -> None:
        self.workspace = workspace
        self.chat_id = str(chat_id or '')
        self.ssh_binary = shutil.which('ssh') or 'ssh'
        self.known_hosts = workspace.meta / 'external_targets_known_hosts'
        self.known_hosts.touch(exist_ok=True)
        try:
            os.chmod(self.known_hosts, 0o600)
        except OSError:
            pass

    def resolve(self, target_id_or_name: str, *, require_enabled: bool = True) -> ExternalTarget:
        target = self.workspace.get_external_target(target_id_or_name)
        if target is None:
            raise ExternalTargetError(f'External target not found: {target_id_or_name}')
        if require_enabled and not target.enabled:
            raise ExternalTargetError(f'External target is disabled: {target.name}')
        return target

    @staticmethod
    def public_target(target: ExternalTarget) -> dict[str, Any]:
        result = {
            'id': target.id,
            'name': target.name,
            'host': target.host,
            'port': target.port,
            'username': target.username,
            'remote_root': target.remote_root,
            'enabled': target.enabled,
            'approval_mode': target.approval_mode,
            'policy': dict(target.policy),
            # Credential contents/path are deliberately not exposed to the model.
            'authentication': 'password' if target.auth_method == 'password' else (
                'identity-file' if target.identity_file else 'ssh-agent/default-keys'
            ),
        }
        if target.managed_vm:
            windows = target.managed_vm.get('os') == 'windows-11'
            result.update(kind='managed_test_vm', guest_os=target.managed_vm.get('os'),
                          architecture=target.managed_vm.get('architecture'), shell='PowerShell' if windows else ('ash' if str(target.managed_vm.get('os')).startswith('openwrt-') else 'bash'),
                          internet=True, software_installation=True, authentication='host-managed Lima',
                          role='Separate test target. Develop in the workspace; copy files here to install, run and test.')
            result['policy'].update(mode='managed_test_vm', allow_privileged=True)
            if str(target.managed_vm.get('os')).startswith('openwrt-'):
                from harnessy.environment.test_radios import public_radio_snapshot
                requested = target.managed_vm.get('emulation', {})
                requested = requested if isinstance(requested, dict) else {}
                result['hardware_emulation'] = public_radio_snapshot({
                    kind: {'requested': requested.get(kind) is True,
                           'status': 'unverified' if requested.get(kind) is True else 'disabled',
                           'reason': 'not_detected' if requested.get(kind) is True else 'not_requested'}
                    for kind in ('wifi', 'bluetooth')
                })
                result['hardware_emulation'].update(
                    current_state_verified=False,
                    verify_with='target_status',
                    scope='Guest software radios only. No physical RF, nearby devices, USB dongle or chipset emulation.',
                )
                result['authentication'] = 'host-managed OpenSSH'
        else:
            result['kind'] = 'external_ssh'
        return result

    def list_public(self) -> list[dict[str, Any]]:
        results = []
        for target in self.workspace.list_external_targets(enabled_only=True):
            item = self.public_target(target)
            if str(target.managed_vm.get('os')).startswith('openwrt-'):
                from harnessy.environment.test_targets import TestTargetManager
                item['hardware_emulation'].update(TestTargetManager(self.workspace, target).radio_state())
            results.append(item)
        return results

    def _ssh_argv(self, target: ExternalTarget) -> list[str]:
        password_auth = target.auth_method == 'password'
        argv = [
            self.ssh_binary,
            '-o', f'BatchMode={"no" if password_auth else "yes"}',
            '-o', 'ConnectTimeout=10',
            '-o', 'ServerAliveInterval=10',
            '-o', 'ServerAliveCountMax=2',
            '-o', 'StrictHostKeyChecking=accept-new',
            '-o', f'UserKnownHostsFile={self.known_hosts}',
            '-p', str(target.port),
        ]
        if password_auth:
            argv += [
                '-o', 'PreferredAuthentications=password,keyboard-interactive',
                '-o', 'PubkeyAuthentication=no',
                '-o', 'NumberOfPasswordPrompts=1',
            ]
        if target.identity_file:
            key = Path(target.identity_file).expanduser()
            if not key.is_file():
                raise ExternalTargetError('Configured SSH identity file does not exist on the HarnessyXO host.')
            argv += ['-o', 'IdentitiesOnly=yes', '-i', str(key)]
        argv.append(f'{target.username}@{target.host}')
        return argv

    @staticmethod
    def _relative_remote_path(value: str, *, allow_dot: bool = True) -> str:
        raw = str(value or '.').strip().replace('\\', '/') or '.'
        path = PurePosixPath(raw)
        if path.is_absolute():
            raise ExternalTargetError('Remote paths must be relative to the configured target root.')
        if ':' in raw or any(c in raw for c in ('\x00', '\r', '\n')):
            raise ExternalTargetError('Remote paths cannot contain drive letters, streams, or control characters.')
        if any(part in {'..', ''} for part in path.parts):
            raise ExternalTargetError('Remote path traversal is not allowed.')
        normalized = path.as_posix()
        if normalized == '.' and not allow_dot:
            raise ExternalTargetError('A file path is required.')
        return normalized

    @staticmethod
    def _remote_join(root: str, relative: str) -> str:
        base = root.rstrip('/') or '/'
        if relative == '.':
            return base
        return f'{base}/{relative}' if base != '/' else f'/{relative}'

    @staticmethod
    def validate_sandbox_command(command: str, *, remote_root: str = '') -> None:
        text = str(command or '').strip()
        if not text:
            raise ExternalTargetError('Command cannot be empty.')
        if len(text) > 20_000:
            raise ExternalTargetError('Command is too long for external-target execution.')
        if _BLOCKED_COMMAND_RE.search(text):
            raise ExternalTargetError(
                'The external-target sandbox blocks privileged, package/service, raw SSH, firewall, disk, and lateral-network commands. '
                'These actions are not offered by the configured target policy.'
            )
        for match in _BLOCKED_PATH_RE.finditer(text):
            # A root account may deliberately work in its configured /root/
            # subdirectory; unrelated /root paths remain blocked by policy.
            allowed = remote_root if remote_root.startswith('/root/') else ''
            tail = text[match.start() + match.group().find('/'):]
            if match.group().rstrip('/').endswith('/root') and allowed and tail.startswith(allowed):
                after = tail[len(allowed):len(allowed) + 1]
                if not after or after == '/' or after in ' \t\r\n\'\";|&)]':
                    continue
            raise ExternalTargetError('The external-target sandbox blocks direct access to protected system paths.')
        # Restrict obvious parent traversal in model-supplied commands. This is
        # a policy filter; root code can bypass it, and symlinks may escape.
        if re.search(r'(^|[\s/])\.\.(?:/|\s|$)', text):
            raise ExternalTargetError('Parent-directory traversal is blocked for external-target commands.')

    @staticmethod
    def _command_audit_detail(command: str, cwd: str) -> str:
        """Return a useful but privacy-safe command summary for durable audit state."""
        text = str(command or '').strip()
        executable = 'unknown'
        try:
            parts = shlex.split(text, posix=True)
            if parts:
                executable = PurePosixPath(parts[0]).name or 'unknown'
        except ValueError:
            pass
        executable = re.sub(r'[^A-Za-z0-9_.+-]+', '_', executable)[:80] or 'unknown'
        return f'cwd={cwd} executable={executable} command_chars={len(text)}'

    async def _run_ssh(
        self, target: ExternalTarget, remote_command: str, *, timeout: float = 120.0,
        input_bytes: bytes | None = None, max_output_chars: int = 80_000,
    ) -> TargetCommandResult:
        started = time.perf_counter()
        try:
            proc, cleanup = await self._start_ssh(
                target, remote_command,
                stdin=asyncio.subprocess.PIPE if input_bytes is not None else asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(input_bytes), timeout=max(1.0, float(timeout)))
            finally:
                if proc.returncode is None:
                    proc.kill()
                    await proc.communicate()
                await cleanup()
        except FileNotFoundError as exc:
            raise ExternalTargetError('OpenSSH client was not found on the HarnessyXO host.') from exc
        duration = max(0.0, time.perf_counter() - started)
        stdout = stdout_b.decode('utf-8', errors='replace')
        stderr = stderr_b.decode('utf-8', errors='replace')
        if len(stdout) > max_output_chars:
            stdout = stdout[:max_output_chars] + '\n...[stdout truncated by HarnessyXO]'
        if len(stderr) > max_output_chars:
            stderr = stderr[:max_output_chars] + '\n...[stderr truncated by HarnessyXO]'
        return TargetCommandResult(proc.returncode == 0, proc.returncode, stdout, stderr, duration)

    async def _start_ssh(
        self, target: ExternalTarget, command: str, **kwargs: Any,
    ) -> tuple[asyncio.subprocess.Process, Callable[[], Awaitable[None]]]:
        if target.managed_vm:
            from harnessy.environment.test_targets import TestTargetManager
            manager = TestTargetManager(self.workspace, target)
            # Start's own readiness probe is allowed; data operations cannot
            # race a stopped-VM snapshot or restore.
            if manager.busy and manager.operation.action != 'start':
                operation = manager.operation
                # Radio setup and shutdown cleanup use this transport only
                # from their owning lifecycle task. Other commands stay blocked.
                owned_lifecycle_task = (operation.action in {'radios', 'stop'}
                                        and operation.task is asyncio.current_task())
                if not owned_lifecycle_task:
                    raise ExternalTargetError('A test VM lifecycle operation is running.')
            argv, env = manager.command(command)
            release = manager.acquire()
            async def managed_cleanup():
                release()
            try:
                return await asyncio.create_subprocess_exec(*argv, env=env, cwd=manager.root, **kwargs), managed_cleanup
            except BaseException:
                release()
                raise
        argv = self._ssh_argv(target) + [command]
        async def no_cleanup() -> None:
            pass
        if target.auth_method != 'password':
            return await asyncio.create_subprocess_exec(*argv, **kwargs), no_cleanup
        password = TargetCredentialStore().get(self.workspace.id, target.id)
        if password is None:
            raise ExternalTargetError('SSH password is missing. Edit this target and enter its password again.')
        helper = Path(__file__).with_name('ssh_askpass.py')
        if not helper.is_file() or not os.access(helper, os.R_OK):
            raise ExternalTargetError('OpenSSH password helper is unavailable or unreadable.')
        temp_dir = tempfile.TemporaryDirectory(prefix='hxa-')
        pipe_path = str(Path(temp_dir.name) / 'password.pipe')
        launcher = Path(temp_dir.name) / 'askpass'
        keep_reader = -1
        try:
            # ZIP extractors may discard the helper's executable bit. OpenSSH
            # requires an executable SSH_ASKPASS program; create one in this
            # private per-request directory instead of depending on ZIP modes.
            launcher.write_text(
                '#!/bin/sh\nexec ' + shlex.quote(sys.executable) + ' '
                + shlex.quote(str(helper)) + ' "$@"\n', encoding='utf-8',
            )
            launcher.chmod(0o700)
            os.mkfifo(pipe_path, 0o600)
            keep_reader = os.open(pipe_path, os.O_RDONLY | os.O_NONBLOCK)
            writer = os.open(pipe_path, os.O_WRONLY | os.O_NONBLOCK)
            try:
                data = password.encode('utf-8')
                if os.write(writer, data) != len(data):
                    raise ExternalTargetError('Could not prepare the SSH password prompt.')
            finally:
                os.close(writer)
        except BaseException:
            if keep_reader >= 0:
                os.close(keep_reader)
            temp_dir.cleanup()
            raise
        env = dict(os.environ)
        env.update({
            'SSH_ASKPASS': str(launcher), 'SSH_ASKPASS_REQUIRE': 'force',
            'DISPLAY': env.get('DISPLAY') or 'harnessyxo:0',
            'HARNESSY_SSH_ASKPASS_PIPE': pipe_path,
        })
        async def cleanup() -> None:
            os.close(keep_reader)
            temp_dir.cleanup()
        try:
            proc = await asyncio.create_subprocess_exec(*argv, env=env, **kwargs)
        except BaseException:
            await cleanup()
            raise
        return proc, cleanup

    @staticmethod
    def _windows(target: ExternalTarget) -> bool:
        return target.managed_vm.get('os') == 'windows-11'

    @staticmethod
    def _ps_literal(value: str) -> str:
        return "'" + str(value).replace("'", "''") + "'"

    @staticmethod
    def _powershell(script: str) -> str:
        wrapper = ("$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; "
                   "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); "
                   "try { " + script + "; if ($LASTEXITCODE -is [int]) { exit $LASTEXITCODE } } "
                   "catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }")
        encoded = base64.b64encode(wrapper.encode('utf-16-le')).decode('ascii')
        if len(encoded) > 7500:
            raise ExternalTargetError('Windows command is too long. Copy a .ps1 script with target_copy_to and run that file.')
        return 'powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand ' + encoded

    @staticmethod
    def _hostname_probe() -> str:
        # OpenWrt's minimal BusyBox build need not ship a hostname applet.
        # Host identity is descriptive metadata, not a readiness dependency.
        return ('if command -v hostname >/dev/null 2>&1; then hostname 2>/dev/null || printf "unknown\\n"; '
                'elif IFS= read -r hx_host < /proc/sys/kernel/hostname; then printf "%s\\n" "$hx_host"; '
                'else printf "unknown\\n"; fi')

    async def test_connection(self, target: ExternalTarget, *, initialize_root: bool = False,
                              timeout: float = 20, require_bootstrap: bool = False,
                              audit: bool = True) -> dict[str, Any]:
        root_q = shlex.quote(target.remote_root)
        action = 'mkdir -p -- ' + root_q if initialize_root else 'test -d ' + root_q
        command = (
            ('test -f /etc/harnessy-test-ready || exit 74; ' if require_bootstrap else '') +
            f'{action} || exit 72; '
            f'test -w {root_q} || {{ printf "HX_ROOT_NOT_WRITABLE\\n" >&2; exit 73; }}; '
            f'printf "HX_OK\\n" && '
            f'printf "USER="; id -un 2>/dev/null || printf "unknown\\n"; '
            f'printf "HOST="; {self._hostname_probe()}; '
            f'printf "ROOT_WRITABLE=yes\\n"'
        )
        if self._windows(target):
            root = self._ps_literal(target.remote_root)
            command = self._powershell(
                (f"[IO.Directory]::CreateDirectory({root}) | Out-Null; " if initialize_root else '') +
                f"if (!(Test-Path -LiteralPath {root} -PathType Container)) {{ throw 'Test root does not exist' }}; "
                "Write-Output 'HX_OK'; Write-Output ('USER=' + $env:USERNAME); Write-Output ('HOST=' + $env:COMPUTERNAME)"
            )
        result = await self._run_ssh(target, command, timeout=timeout)
        if audit:
            self.workspace.record_external_target_event(
                target.id, chat_id=self.chat_id, action='connection_test',
                detail='initialize_root=true' if initialize_root else 'initialize_root=false',
                ok=result.ok, returncode=result.returncode, duration_seconds=result.duration_seconds,
            )
        return {
            'ok': result.ok,
            'target': self.public_target(target),
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode,
            'duration_seconds': result.duration_seconds,
        }

    async def status(self, target: ExternalTarget) -> dict[str, Any]:
        vm_status = None
        if target.managed_vm:
            from harnessy.environment.test_targets import TestTargetManager
            manager = TestTargetManager(self.workspace, target)
            vm_status = await manager.status()
            operation = manager.operation
            vm_status['operation'] = {'action': operation.action, 'state': operation.state, 'error': operation.error} if operation else None
            vm_status['snapshots'] = manager.snapshots()
            if manager.guest.family == 'openwrt':
                vm_status['hardware_emulation'] = manager.radio_state()
            if not vm_status['running'] or manager.busy:
                return {'ok': True, 'target': self.public_target(target), 'vm': vm_status}
        root_q = shlex.quote(target.remote_root)
        command = (
            'printf "USER="; id -un; '
            f'printf "HOST="; {self._hostname_probe()}; '
            'printf "KERNEL="; uname -sr; '
            f'printf "ROOT_EXISTS="; if test -d {root_q}; then echo yes; else echo no; fi; '
            f'printf "ROOT_WRITABLE="; if test -w {root_q}; then echo yes; else echo no; fi'
        )
        if self._windows(target):
            command = self._powershell("Write-Output ('USER=' + $env:USERNAME); Write-Output ('HOST=' + $env:COMPUTERNAME); "
                f"Write-Output ('ROOT_EXISTS=' + (Test-Path -LiteralPath {self._ps_literal(target.remote_root)} -PathType Container))")
        result = await self._run_ssh(target, command, timeout=20)
        self.workspace.record_external_target_event(
            target.id, chat_id=self.chat_id, action='status', ok=result.ok,
            returncode=result.returncode, duration_seconds=result.duration_seconds,
        )
        target_public = self.public_target(target)
        if vm_status is not None and manager.guest.family == 'openwrt' and result.ok:
            snapshot = await manager.inspect_radios()
            vm_status['hardware_emulation'] = snapshot
            target_public['hardware_emulation'].update(snapshot)
        return {
            'ok': result.ok, 'target': target_public, 'stdout': result.stdout,
            'stderr': result.stderr, 'returncode': result.returncode,
            'duration_seconds': result.duration_seconds,
            'vm': vm_status,
        }

    async def exec(
        self, target: ExternalTarget, command: str, *, cwd: str = '.', timeout: float = 180.0,
    ) -> dict[str, Any]:
        if not target.policy.get('allow_exec', True):
            raise ExternalTargetError('Command execution is disabled for this target.')
        if target.managed_vm:
            if not str(command).strip() or len(command) > 20000:
                raise ExternalTargetError('Target command must contain 1–20000 characters.')
        else:
            self.validate_sandbox_command(command, remote_root=target.remote_root)
        cwd_rel = self._relative_remote_path(cwd)
        workdir = self._remote_join(target.remote_root, cwd_rel)
        remote = (
            f'test -d {shlex.quote(workdir)} || {{ echo "HarnessyXO target cwd does not exist" >&2; exit 72; }}; '
            f'cd -- {shlex.quote(workdir)} && '
            f'export HOME={shlex.quote(target.remote_root)} TMPDIR={shlex.quote(self._remote_join(target.remote_root, ".tmp"))}; '
            f'mkdir -p -- "$TMPDIR"; '
            f'sh -lc {shlex.quote(str(command))}'
        )
        if self._windows(target):
            remote = self._powershell(f"Set-Location -LiteralPath {self._ps_literal(workdir)}; " + str(command))
        result = await self._run_ssh(target, remote, timeout=max(1.0, min(float(timeout), 7200.0)))
        self.workspace.record_external_target_event(
            target.id, chat_id=self.chat_id, action='exec',
            detail=self._command_audit_detail(command, cwd_rel), ok=result.ok,
            returncode=result.returncode, duration_seconds=result.duration_seconds,
        )
        return {
            'ok': result.ok, 'target': self.public_target(target), 'cwd': cwd_rel,
            'returncode': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr,
            'duration_seconds': result.duration_seconds,
        }

    async def list_files(self, target: ExternalTarget, *, path: str = '.', max_depth: int = 2, max_entries: int = 300) -> dict[str, Any]:
        if not target.policy.get('allow_list', True):
            raise ExternalTargetError('Remote file listing is disabled for this target.')
        rel = self._relative_remote_path(path)
        remote_path = self._remote_join(target.remote_root, rel)
        depth = max(0, min(int(max_depth), 6))
        entries = max(1, min(int(max_entries), 2000))
        # Fixed command: the model cannot escape the configured root through this tool.
        command = (
            f'test -d {shlex.quote(remote_path)} || exit 72; '
            f'cd -- {shlex.quote(remote_path)} && '
            f'find . -mindepth 1 -maxdepth {depth + 1} -print | head -n {entries}'
        )
        if self._windows(target):
            command = self._powershell(
                f"Get-ChildItem -LiteralPath {self._ps_literal(remote_path)} -Force -Recurse -Depth {depth} | "
                f"Select-Object -First {entries} -Property FullName,Length,PSIsContainer | ConvertTo-Json -Compress")
        result = await self._run_ssh(target, command, timeout=60)
        self.workspace.record_external_target_event(
            target.id, chat_id=self.chat_id, action='list_files', detail=f'path={rel}',
            ok=result.ok, returncode=result.returncode, duration_seconds=result.duration_seconds,
        )
        return {
            'ok': result.ok, 'target': self.public_target(target), 'path': rel,
            'stdout': result.stdout, 'stderr': result.stderr, 'returncode': result.returncode,
        }

    @staticmethod
    def _local_path_under(root: Path, value: str, *, must_exist: bool) -> Path:
        root = root.resolve()
        candidate = (root / str(value or '')).resolve(strict=False)
        if candidate != root and root not in candidate.parents:
            raise ExternalTargetError('Local path is outside the active HarnessyXO working root.')
        if must_exist and not candidate.is_file():
            raise ExternalTargetError('Local source file does not exist or is not a regular file.')
        return candidate

    async def copy_to(self, target: ExternalTarget, *, local_root: Path, local_path: str, remote_path: str, timeout: float = 300.0) -> dict[str, Any]:
        if not target.policy.get('allow_copy_to', True):
            raise ExternalTargetError('Copy-to-target is disabled for this target.')
        source = self._local_path_under(local_root, local_path, must_exist=True)
        if source.stat().st_size > 256 * 1024 * 1024:
            raise ExternalTargetError('External-target copy is limited to 256 MiB per file in v0.4.')
        rel = self._relative_remote_path(remote_path, allow_dot=False)
        dest = self._remote_join(target.remote_root, rel)
        data = source.read_bytes()
        remote = f'mkdir -p -- {shlex.quote(str(PurePosixPath(dest).parent))} && cat > {shlex.quote(dest)}'
        if self._windows(target):
            remote = self._powershell(
                f"$dest={self._ps_literal(dest)}; [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($dest)) | Out-Null; "
                "$file=[IO.File]::Create($dest); try { [Console]::OpenStandardInput().CopyTo($file) } finally { $file.Dispose() }")
        result = await self._run_ssh(target, remote, timeout=max(1.0, min(float(timeout), 7200.0)), input_bytes=data, max_output_chars=20_000)
        self.workspace.record_external_target_event(
            target.id, chat_id=self.chat_id, action='copy_to', detail=f'{local_path} -> {rel}',
            ok=result.ok, returncode=result.returncode, duration_seconds=result.duration_seconds,
        )
        return {
            'ok': result.ok, 'target': self.public_target(target), 'local_path': str(local_path),
            'remote_path': rel, 'bytes': len(data), 'stderr': result.stderr,
            'returncode': result.returncode, 'duration_seconds': result.duration_seconds,
        }

    async def copy_from(self, target: ExternalTarget, *, local_root: Path, remote_path: str, local_path: str, timeout: float = 300.0) -> dict[str, Any]:
        if not target.policy.get('allow_copy_from', True):
            raise ExternalTargetError('Copy-from-target is disabled for this target.')
        rel = self._relative_remote_path(remote_path, allow_dot=False)
        source = self._remote_join(target.remote_root, rel)
        dest = self._local_path_under(local_root, local_path, must_exist=False)
        dest.parent.mkdir(parents=True, exist_ok=True)
        started = time.perf_counter()
        remote = f'test -f {shlex.quote(source)} && cat -- {shlex.quote(source)}'
        if self._windows(target):
            remote = self._powershell(
                f"$file=[IO.File]::OpenRead({self._ps_literal(source)}); "
                "try { $file.CopyTo([Console]::OpenStandardOutput()) } finally { $file.Dispose() }")
        try:
            proc, cleanup = await self._start_ssh(
                target, remote,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise ExternalTargetError('OpenSSH client was not found on the HarnessyXO host.') from exc
        received = 0
        tmp = dest.with_name(f'.{dest.name}.hxtmp')
        try:
            async def transfer() -> tuple[int, bytes]:
                nonlocal received
                assert proc.stdout is not None
                assert proc.stderr is not None
                with tmp.open('wb') as stream:
                    while True:
                        chunk = await proc.stdout.read(256 * 1024)
                        if not chunk:
                            break
                        received += len(chunk)
                        if received > 256 * 1024 * 1024:
                            raise ExternalTargetError('External-target copy is limited to 256 MiB per file in v0.4.')
                        stream.write(chunk)
                stderr_b = await proc.stderr.read()
                return await proc.wait(), stderr_b
            try:
                returncode, stderr_b = await asyncio.wait_for(transfer(), timeout=max(1.0, min(float(timeout), 7200.0)))
            except Exception:
                proc.kill()
                await proc.wait()
                raise
            stderr = stderr_b.decode('utf-8', errors='replace')
            ok = returncode == 0
            if ok:
                tmp.replace(dest)
            else:
                tmp.unlink(missing_ok=True)
        finally:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()
            await cleanup()
        duration = max(0.0, time.perf_counter() - started)
        self.workspace.record_external_target_event(
            target.id, chat_id=self.chat_id, action='copy_from', detail=f'{rel} -> {local_path}',
            ok=ok, returncode=returncode, duration_seconds=duration,
        )
        return {
            'ok': ok, 'target': self.public_target(target), 'remote_path': rel,
            'local_path': str(local_path), 'bytes': received if ok else 0,
            'stderr': stderr, 'returncode': returncode, 'duration_seconds': duration,
        }
