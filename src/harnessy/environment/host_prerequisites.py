"""Workspace and test-target host prerequisites, shared by startup and Start.

Standard-library only. Uses fixed argv, repairs discovery before installing,
never changes a guest network policy or rebuilds a workspace. Package-manager
failures are actionable; privileges are never solicited through the browser.
"""
from __future__ import annotations
import asyncio
import errno
import json
import os
import platform
import re
import shutil
import signal
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from .presets import canonical_arch, execution_mode

_KNOWN_BIN_DIRS = ('/opt/homebrew/bin', '/opt/homebrew/sbin', '/usr/local/bin',
                   '/usr/local/sbin', '/usr/bin', '/usr/sbin', '/bin', '/sbin',
                   '/home/linuxbrew/.linuxbrew/bin', '/opt/local/bin')
_E2FS_PREFIXES = ('/opt/homebrew/opt/e2fsprogs', '/usr/local/opt/e2fsprogs',
                  '/home/linuxbrew/.linuxbrew/opt/e2fsprogs')
_TARGET_QEMU_BINARIES = {
    'x86_64': 'qemu-system-x86_64', 'arm64': 'qemu-system-aarch64',
    'mips': 'qemu-system-mips', 'mipsel': 'qemu-system-mipsel',
    'mips64': 'qemu-system-mips64', 'mips64el': 'qemu-system-mips64el',
}
_TARGET_COMMON_BINARIES = ('qemu-img', 'ssh', 'ssh-keygen')
_E2FS_BINARIES = ('debugfs', 'e2fsck', 'resize2fs')
_INSTALL_LOCKS: dict[int, asyncio.Lock] = {}
_TERMINAL_AUTH_ATTEMPTED = False
_OUTPUT_TRUNCATED = '[HarnessyXO output truncated]'
_HOST_COMMAND_HEARTBEAT_SECONDS = 5.0
_HOST_OBSERVATION_CALLBACK_TIMEOUT_SECONDS = 1.0


class HostPrerequisiteError(RuntimeError):
    code = 'setup_failed'

    def __init__(self, message: str, *, code: str | None = None):
        super().__init__(message)
        if code is not None:
            self.code = code


class HostKVMAccessError(HostPrerequisiteError):
    code = 'KVM_ACCESS_DENIED'


def _effective_kvm_access() -> bool:
    try:
        return os.access('/dev/kvm', os.R_OK | os.W_OK, effective_ids=True)
    except (TypeError, NotImplementedError):
        # Older Python/platform builds may lack effective-ID access checks.
        # A real-ID check is equivalent only when real/effective identities match.
        if ((getattr(os, 'getuid', lambda: None)() != getattr(os, 'geteuid', lambda: None)())
                or (getattr(os, 'getgid', lambda: None)() != getattr(os, 'getegid', lambda: None)())):
            return False
        return os.access('/dev/kvm', os.R_OK | os.W_OK)


def validate_native_kvm_access(architecture: str, vm_type: str) -> dict[str, Any]:
    """Check Lima's native Linux KVM selection without starting a guest.

    Lima selects KVM when the native Linux host can stat /dev/kvm; a later
    permission failure does not trigger its absent-device TCG fallback.
    """
    host_os = platform.system()
    host_arch = canonical_arch(platform.machine())
    foreign = canonical_arch(architecture) != host_arch
    present = host_os == 'Linux' and Path('/dev/kvm').exists()
    accessible = bool(present and _effective_kvm_access())
    report = {'host_os': host_os, 'host_architecture': host_arch, 'vm_type': vm_type,
              'foreign_architecture': foreign, 'kvm_present': present, 'kvm_accessible': accessible}
    if host_os != 'Linux' or vm_type != 'qemu' or foreign or not present:
        return report
    active_group: bool | None = None
    try:
        device_gid = Path('/dev/kvm').stat().st_gid
        active_group = device_gid == os.getegid() or device_gid in os.getgroups()
        report['kvm_device_group_active'] = active_group
    except (OSError, AttributeError):
        pass
    denied: OSError | None = None
    if accessible:
        try:
            descriptor = os.open('/dev/kvm', os.O_RDWR | getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_NONBLOCK', 0))
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EPERM}:
                denied = exc
                accessible = False
                report['kvm_accessible'] = False
            else:
                # An unavailable driver is not evidence that adding a group
                # will repair it. Do not create a VM or choose TCG here.
                number = f' (errno {exc.errno})' if isinstance(exc.errno, int) else ''
                raise HostPrerequisiteError(
                    '[KVM_UNAVAILABLE] /dev/kvm could not be opened' + number + '. '
                    'Check the host KVM driver/device configuration, then retry Start. '
                    'The guest does not need a reset or rebuild for this host check.'
                ) from exc
        else:
            os.close(descriptor)  # Opening the subsystem handle creates no VM; no ioctl is issued.
    if not accessible:
        if active_group:
            repair = (
                'This process already has the device group. Check host ACLs and service/container '
                'device-security restrictions; adding the same group again will not repair that denial. '
            )
        else:
            repair = (
                'Stop HarnessyXO and add your normal host account to the group owning /dev/kvm '
                '(usually kvm; for example: sudo usermod -aG kvm "$(id -un)"). '
                'Sign out and back in, or open a host shell with newgrp kvm, then restart python3 run.py '
                'from that fresh session. Existing processes keep their old groups even if the account '
                'has already been added. A service/container must also receive the device group/access. '
            )
        error = HostKVMAccessError(
            '[KVM_ACCESS_DENIED] The HarnessyXO process cannot read and write /dev/kvm. '
            'Lima selects KVM for this native Linux VM and will fail to start it. '
            + repair +
            'Guest reset or rebuild is not needed for this host permission repair.'
        )
        error.kvm_device_group_active = active_group
        if denied is not None:
            error.errno = denied.errno
            raise error from denied
        raise error
    return report


def repaired_path(path: str | None = None) -> str:
    entries = (os.environ.get('PATH', '') if path is None else path).split(os.pathsep)
    # Empty PATH entries mean CWD; do not introduce implicit host-workspace
    # command execution while repairing a GUI-launched process's PATH.
    entries = [entry for entry in entries if entry and Path(entry).is_absolute()]
    if platform.system() == 'Linux':
        from .managed_lima import managed_bin_directory, tool_root
        managed = managed_bin_directory()
        releases = tool_root() / 'releases'
        # A cache invalidated in this process must not remain executable merely
        # because an earlier discovery appended it to PATH. User-installed
        # controllers outside our private cache keep their original priority.
        entries = [entry for entry in entries
                   if not (Path(entry).parent.parent == releases and Path(entry).name == 'bin')
                   or (managed is not None and Path(entry) == managed)]
    for entry in (*_KNOWN_BIN_DIRS, str(Path.home() / '.local/bin')):
        if entry not in entries and Path(entry).is_dir():
            entries.append(entry)
    # e2fsprogs is deliberately keg-only in Homebrew. Discover the existing
    # opt links without brew link --force or changing the user's shell PATH.
    for prefix in _E2FS_PREFIXES:
        for suffix in ('bin', 'sbin'):
            entry = str(Path(prefix) / suffix)
            if entry not in entries and Path(entry).is_dir():
                entries.append(entry)
    if platform.system() == 'Linux':
        if managed is not None and str(managed) not in entries:
            entries.append(str(managed))
    return os.pathsep.join(entries)


def restore_host_tool_path() -> None:
    """Repair only this process's PATH from a verified existing tools cache."""
    os.environ['PATH'] = repaired_path()


def discover_binary(name: str) -> str | None:
    path = repaired_path()
    found = shutil.which(name, path=path)
    if found:
        # Repair only this process environment, not shell rc files or symlinks.
        os.environ['PATH'] = path
    return found


def required_binaries(architecture: str, vm_type: str) -> tuple[str, ...]:
    names = ['limactl', 'ssh', 'ssh-keygen']
    if vm_type == 'qemu':
        suffix = 'aarch64' if canonical_arch(architecture) == 'arm64' else 'x86_64'
        names += ['qemu-system-' + suffix, 'qemu-img', 'qemu-firmware-' + suffix]
    return tuple(names)


def test_target_qemu_binary(architecture: str) -> str:
    architecture = 'arm64' if architecture == 'aarch64' else architecture
    if architecture not in _TARGET_QEMU_BINARIES:
        raise HostPrerequisiteError(f'Unsupported test-target architecture: {architecture}.')
    return _TARGET_QEMU_BINARIES[architecture]


def test_target_required_binaries(architecture: str | None = None, *, windows: bool = False) -> tuple[str, ...]:
    """Host executables for one target, or the full supported target catalogue.

    This list is independent of saved workspaces: first startup prepares MIPS
    and Windows support even before a user creates their first test target.
    """
    if architecture is None:
        from .test_catalog import GUESTS, target_architectures
        supported = {('arm64' if arch == 'aarch64' else arch)
                     for guest in GUESTS for arch in target_architectures(guest)}
        unmapped = supported.difference(_TARGET_QEMU_BINARIES)
        if unmapped:
            raise HostPrerequisiteError('The test-target catalogue advertises architectures without host prerequisite mappings: '
                                        + ', '.join(sorted(unmapped)) + '. Host setup is incomplete.')
        qemu = tuple(binary for arch, binary in _TARGET_QEMU_BINARIES.items() if arch in supported)
        return (*qemu, *_TARGET_COMMON_BINARIES, *_E2FS_BINARIES, 'swtpm')
    names = (test_target_qemu_binary(architecture), *_TARGET_COMMON_BINARIES)
    return (*names, 'swtpm') if windows else (*names, *_E2FS_BINARIES)


async def _progress(callback, phase: str, message: str, **meta) -> None:
    if callback:
        result = callback(phase, message, **meta)
        if asyncio.iscoroutine(result):
            await result


def _record_host_setup(scope: str, architecture: str | None, status: str, *, required=(), missing=(), broken=(),
                       error_code: str | None = None, manager: str | None = None, packages=(),
                       returncode: int | None = None, planned_formulae=(),
                       vm_infrastructure_active: bool | None = None) -> None:
    """Content-free fixed host-tool receipts survive ordinary diagnostics."""
    try:
        from ..diagnostics import log_event
        fields: dict[str, Any] = {'scope': scope, 'status': status,
                                  'required_binaries': list(required), 'missing_binaries': list(missing),
                                  'broken_binaries': list(broken)}
        if architecture is None:
            fields['architecture'] = 'all'
        else:
            value = 'arm64' if architecture == 'aarch64' else architecture
            if value in _TARGET_QEMU_BINARIES:
                fields['architecture'] = value
        if error_code:
            fields['error_code'] = error_code
        if manager:
            fields['manager'] = manager
            fields['packages'] = list(packages)
        if returncode is not None:
            fields['returncode'] = int(returncode)
        if planned_formulae:
            fields['planned_formulae'] = list(planned_formulae)
        if isinstance(vm_infrastructure_active, bool):
            fields['vm_infrastructure_active'] = vm_infrastructure_active
        log_event('runtime', 'host_prerequisite_setup', **fields)
    except Exception:
        # Optional diagnostics must never prevent or mask host setup itself.
        pass


def _attach_report(error: HostPrerequisiteError, report: dict[str, Any]) -> None:
    if report:
        if not hasattr(error, 'missing_binaries'):
            error.missing_binaries = tuple(report.get('missing', ()))
        if not hasattr(error, 'broken_binaries'):
            error.broken_binaries = tuple(report.get('broken', ()))


async def _run_command(argv: list[str], *, env: dict[str, str] | None = None,
                       timeout: float = 30, progress=None, retain_session: bool = False,
                       terminal_input: bool = False) -> tuple[int, str]:
    """Bounded fixed host invocation with content-free process observations."""
    from harnessy.diagnostics import log_event
    from harnessy.diagnostics.controller_observations import HOST_PROGRAMS, validate_controller_observation
    from .manager import current_environment_operation
    from .operations import current_controller_operation_context

    context, observer = current_controller_operation_context()
    context = {**current_environment_operation(), **context}
    package_programs = {'apt', 'apt-get', 'brew', 'dnf', 'yum', 'apk', 'pacman', 'zypper'}
    candidates = [Path(value).name for value in argv[:5] if isinstance(value, str)]
    package = next((value for value in candidates if value in package_programs), None)
    program = package or (candidates[0] if candidates and candidates[0] in HOST_PROGRAMS else 'other')
    action = 'package_manager' if package is not None else 'prerequisite_check'
    command_id, started = uuid.uuid4().hex, time.monotonic()
    proc = heartbeat = None
    observed_bytes = 0
    last_output_at = None
    terminal = 'environment_controller_finished'
    outcome = 'running'
    interrupted_during_cleanup = False
    chunks: list[str] = []
    truncated = False

    async def emit(event):
        now = time.monotonic()
        fields = dict(provider='host', command_id=command_id, controller_action=action,
            controller_program=program, controller_state='not_started' if proc is None else
                'running' if proc.returncode is None else 'exited',
            completion_phase='running_controller', elapsed_seconds=max(0.0, now - started),
            timeout_seconds=max(0.0, float(timeout)), controller_returncode=None if proc is None else proc.returncode,
            output_capture='inherited_terminal' if terminal_input else 'merged_pipe',
            capture_scope='direct_controller_lifetime' if terminal_input else 'command_output_lifetime',
            outcome=outcome, **context)
        if proc is not None:
            fields['controller_pid'] = proc.pid
        if not terminal_input:
            # stderr is merged into stdout. These are observed combined bytes,
            # not separate stderr counts or complete post-cancellation output.
            fields.update(stdout_bytes=observed_bytes,
                last_output_age_seconds=max(0.0, now - (last_output_at or started)))
        safe = validate_controller_observation(event, fields)
        if safe is None:
            return
        try:
            log_event('runtime', event, **{key: value for key, value in safe.items() if key != 'event'})
        except Exception:
            pass
        try:
            if observer is not None:
                await asyncio.wait_for(observer(safe), _HOST_OBSERVATION_CALLBACK_TIMEOUT_SECONDS)
            if progress is not None:
                detail = (f"Host command {action.replace('_', ' ')} · {now - started:.1f}s elapsed · "
                    + ('output is not captured for this interactive command' if terminal_input else
                       f"{observed_bytes} combined output bytes · {now - (last_output_at or started):.1f}s since last output"))
                await asyncio.wait_for(_progress(progress, 'installing_host_dependencies' if action == 'package_manager' else 'checking_host_dependencies', 'Running host prerequisite command…',
                    detail=detail, progress_source='package_manager' if action == 'package_manager' else 'host_prerequisites', controller_observation=safe), _HOST_OBSERVATION_CALLBACK_TIMEOUT_SECONDS)
        except asyncio.CancelledError:
            if asyncio.current_task().cancelling():
                raise
        except Exception:
            pass

    async def pulse():
        while True:
            await asyncio.sleep(_HOST_COMMAND_HEARTBEAT_SECONDS)
            await emit('environment_controller_heartbeat')

    async def settle(task):
        cancelled = False
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                cancelled = True
        task.result()
        return cancelled

    # Preserve the existing sudo session and owned-process-group boundaries.
    private_group = bool(os.name == 'posix' and retain_session and not terminal_input
                         and sys.version_info >= (3, 11))
    group_options = {'process_group': 0} if private_group else {}
    owns_group = os.name == 'posix' and (not retain_session or private_group)

    async def stop_owned():
        if proc is None:
            return
        try:
            if proc.returncode is None or owns_group:
                try:
                    if owns_group:
                        os.killpg(proc.pid, signal.SIGTERM)
                    else:
                        proc.terminate()
                    await asyncio.wait_for(proc.wait(), 5)
                except (ProcessLookupError, asyncio.TimeoutError):
                    if owns_group:
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    elif proc.returncode is None:
                        proc.kill()
        finally:
            # An escaped session may keep the inherited writer open. Close
            # only our captured reader after failure/cancellation; never kill
            # an unowned descendant or wait for its pipe EOF.
            transport = getattr(proc.stdout, '_transport', None)
            if transport is not None:
                transport.close()
            if proc.returncode is None:
                await proc.wait()

    async def drain():
        nonlocal truncated, observed_bytes, last_output_at
        if proc.stdout is None:
            return await proc.wait()
        while data := await proc.stdout.read(4096):
            observed_bytes += len(data)
            last_output_at = time.monotonic()
            chunks.append(data.decode('utf-8', errors='replace'))
            if sum(map(len, chunks)) > 64000:
                truncated = True
                chunks[:] = [''.join(chunks)[-48000:]]
        return await proc.wait()

    try:
        await emit('environment_controller_started')
        heartbeat = asyncio.create_task(pulse(), name='harnessy-host-command-heartbeat')
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv, stdin=None if terminal_input else asyncio.subprocess.DEVNULL,
                stdout=None if terminal_input else asyncio.subprocess.PIPE,
                stderr=None if terminal_input else asyncio.subprocess.STDOUT,
                env=env, start_new_session=(os.name == 'posix' and not retain_session), **group_options,
            )
        except (OSError, ValueError):
            terminal, outcome = 'environment_controller_spawn_failed', 'spawn_failed'
            raise
        code = await asyncio.wait_for(drain(), timeout)
        outcome = 'succeeded' if code == 0 else 'failed'
    except asyncio.TimeoutError:
        terminal, outcome = 'environment_controller_timed_out', 'timed_out'
        interrupted_during_cleanup = await settle(asyncio.create_task(stop_owned())) or interrupted_during_cleanup
        raise
    except asyncio.CancelledError:
        terminal, outcome = 'environment_controller_cancelled', 'cancelled'
        interrupted_during_cleanup = await settle(asyncio.create_task(stop_owned())) or interrupted_during_cleanup
        raise
    except BaseException:
        if outcome != 'spawn_failed':
            outcome = 'failed'
            interrupted_during_cleanup = await settle(asyncio.create_task(stop_owned())) or interrupted_during_cleanup
        raise
    finally:
        cleanup_cancelled = interrupted_during_cleanup
        if heartbeat is not None:
            heartbeat.cancel()
            cleanup_cancelled = await settle(asyncio.gather(heartbeat, return_exceptions=True)) or cleanup_cancelled
        cleanup_cancelled = await settle(asyncio.create_task(emit(terminal))) or cleanup_cancelled
        if cleanup_cancelled:
            raise asyncio.CancelledError
    output = ''.join(chunks)
    return int(code), (_OUTPUT_TRUNCATED + '\n' + output) if truncated else output


def _version(text: str) -> str:
    match = re.search(r'\b(\d+\.\d+\.\d+)(?:[-+][\w.-]+)?', text)
    return match.group(1) if match else ''


async def _probe_target_binary(name: str, binary: str) -> str:
    """Execute a read-only identity/version check, never a guest or disk tool."""
    if name == 'ssh':
        args, allowed, identity = ['-V'], {0}, r'OpenSSH[_ ]\d+\.\d+'
    elif name == 'ssh-keygen':
        # OpenSSH has no keygen --version flag. Unknown-option help exits 1
        # without prompting, generating a key or opening a supplied file.
        args, allowed, identity = ['-?'], {1}, r'usage:\s*(?:\S*/)?ssh-keygen\b'
    elif name == 'resize2fs':
        # resize2fs prints its version and usage with no device argument.
        args, allowed, identity = [], {1, 2}, r'resize2fs\s+\d+\.\d+'
    elif name in ('debugfs', 'e2fsck'):
        args, allowed, identity = ['-V'], {0}, re.escape(name) + r'\s+\d+\.\d+'
    elif name == 'swtpm':
        # --version is a top-level option. The socket parser treats it as an
        # unknown option on Ubuntu's swtpm and exits with usage help instead.
        args, allowed, identity = ['--version'], {0}, r'(?:swtpm\b|TPM emulator version)[^\n]*\d+\.\d+'
    else:
        args, allowed, identity = ['--version'], {0}, r'(?:QEMU|qemu-img)\b[^\n]*\d+\.\d+'
    try:
        rc, text = await _run_command([binary, *args])
    except (OSError, asyncio.TimeoutError) as exc:
        raise HostPrerequisiteError(f'{name} was found at {binary} but cannot execute its host verification: '
                                    f'{str(exc)[:300] or type(exc).__name__}. Repair that installation and retry.',
                                    code='binary_verification_failed') from None
    if rc not in allowed or re.search(identity, text, re.IGNORECASE) is None:
        raise HostPrerequisiteError(f'{name} was found at {binary} but failed its host verification (exit {rc}): '
                                    f'{text.strip()[-500:] or "no executable identity/version returned"}. '
                                    'Repair this installed binary; no guest reset or rebuild is needed.',
                                    code='binary_verification_failed')
    if name == 'ssh':
        match = re.search(r'OpenSSH[_ ](\d+\.\d+(?:p\d+)?)', text, re.IGNORECASE)
        return match.group(1) if match else 'OpenSSH version verified'
    match = re.search(r'\b\d+\.\d+(?:\.\d+)?(?:p\d+)?\b', text)
    return match.group(0) if match else 'OpenSSH keygen help verified'


async def inspect_test_target_prerequisites(architecture: str | None = None, *, windows: bool = False) -> dict[str, Any]:
    """Inspect the target host tools without relying on existing workspaces."""
    names = test_target_required_binaries(architecture, windows=windows)
    paths = {name: discover_binary(name) for name in names}
    missing = [name for name, path in paths.items() if not path]
    versions: dict[str, str] = {}
    broken: dict[str, str] = {}
    for name, binary in paths.items():
        if binary:
            try:
                versions[name] = await _probe_target_binary(name, binary)
            except HostPrerequisiteError as exc:
                broken[name] = str(exc)
    return {'scope': 'all_test_targets' if architecture is None else 'test_target',
            'architecture': architecture, 'windows': bool(windows), 'paths': paths,
            'missing': missing, 'broken': broken, 'versions': versions,
            'verified': not missing and not broken}


def _guest_agent_path(binary: str, arch: str) -> Path | None:
    name = 'lima-guestagent.Linux-' + ('aarch64' if canonical_arch(arch) == 'arm64' else 'x86_64')
    prefixes = [Path(binary).absolute().parent.parent, Path(binary).resolve().parent.parent]
    for prefix in prefixes:
        for suffix in ('', '.gz'):
            file = prefix / 'share' / 'lima' / (name + suffix)
            if file.is_file() and file.stat().st_size > 0:
                return file
    return None


async def inspect_prerequisites(architecture: str, vm_type: str) -> dict[str, Any]:
    acceleration = validate_native_kvm_access(architecture, vm_type)
    names = required_binaries(architecture, vm_type)
    paths = {name: discover_binary(name) for name in names if not name.startswith('qemu-firmware-')}
    if vm_type == 'qemu':
        from .qemu_firmware import find_qemu_firmware
        suffix = 'aarch64' if canonical_arch(architecture) == 'arm64' else 'x86_64'
        # Firmware is a nonempty regular file, never an executable PATH name.
        paths['qemu-firmware-' + suffix] = find_qemu_firmware(architecture, paths.get('qemu-system-' + suffix))
    missing = [name for name, path in paths.items() if not path]
    version = ''
    if paths.get('limactl'):
        rc, text = await _run_command([paths['limactl'], '--version'])
        if (rc and platform.system() == 'Linux' and os.geteuid() == 0
                and 'must not run as the root user' in text[:1024]):
            raise HostPrerequisiteError('Lima cannot run as root. Start HarnessyXO with your normal user account.')
        version = _version(text)
        if rc or not version or tuple(map(int, version.split('.'))) < (2, 0, 0):
            error = HostPrerequisiteError('Installed Lima must be version 2.0.0 or later and executable. '
                                          f'Observed: {text.strip()[:300] or "unknown"}. No automatic upgrade was attempted.',
                                          code='binary_verification_failed')
            error.broken_binaries = ('limactl',)
            error.missing_binaries = tuple(missing)
            raise error
    foreign = canonical_arch(architecture) != canonical_arch(platform.machine())
    guest_agent = None
    if foreign and paths.get('limactl'):
        guest_agent = _guest_agent_path(paths['limactl'], architecture)
        if guest_agent is None:
            missing.append('lima-additional-guestagents')
        else:
            # Homebrew installs each formula in a versioned keg. A foreign
            # agent must match the installed controller, not the latest formula.
            parts = guest_agent.resolve().parts
            if 'lima-additional-guestagents' in parts:
                index = parts.index('lima-additional-guestagents')
                agent_version = _version(parts[index + 1]) if index + 1 < len(parts) else ''
                if agent_version and agent_version != version:
                    raise HostPrerequisiteError(f'Lima {version} and additional guest agents {agent_version} do not match. '
                                                'Install a matching pair during a maintenance window; no upgrade or VM interruption was attempted.')
    for name in ('qemu-img', 'qemu-system-x86_64', 'qemu-system-aarch64'):
        if paths.get(name):
            rc, text = await _run_command([paths[name], '--version'])
            if rc:
                error = HostPrerequisiteError(f'{name} was found at {paths[name]} but cannot run: {text.strip()[-500:]}. '
                                              'Repair this installation; reinstalling or rebuilding the guest is not a PATH fix.',
                                              code='binary_verification_failed')
                error.broken_binaries = (name,)
                error.missing_binaries = tuple(missing)
                raise error
    return {'paths': paths, 'missing': missing, 'lima_version': version,
            'foreign_architecture': foreign, 'guest_agent': str(guest_agent) if guest_agent else None,
            # Absent-device / foreign-architecture TCG behavior remains Lima's
            # choice. Present-but-inaccessible native KVM is an early error.
            **acceleration}


async def infrastructure_active() -> bool:
    ps = discover_binary('ps')
    if not ps:
        raise HostPrerequisiteError('Cannot verify whether host VM infrastructure is active (ps is missing). '
                                    'Install prerequisites manually after checking active VMs.')
    # Executable names keep inspection bounded even with browsers or build
    # processes carrying very large argument strings. A live limactl process
    # is conservatively treated as active controller infrastructure.
    rc, text = await _run_command([ps, '-axo', 'comm='])
    if rc or _OUTPUT_TRUNCATED in text:
        raise HostPrerequisiteError('Could not inspect active host VM infrastructure. No packages were changed.')
    for line in text.splitlines():
        name = line.strip()
        # macOS ps can wrap its fallback executable name in parentheses when
        # arguments for another account's process cannot be read.
        if name.startswith('(') and name.endswith(')'):
            name = name[1:-1]
        if re.search(r'(?:^|/)(?:qemu-system-[\w-]+|limactl|lima-hostagent)$', name):
            return True
    return False


async def _review_brew_plan(binary: str, packages: list[str], transaction: str, env: dict[str, str], *, progress=None):
    """Verify the CLI plan and required dependency closure before host changes."""
    from dataclasses import replace
    from .brew_plan import BrewPlanError, canonical_formula_name, parse_brew_plan, validate_brew_plan
    facts: list[dict[str, Any]] = []
    try:
        entries = parse_brew_plan(transaction)
        inventory_command = [binary, 'list', '--formula', '--versions']
        await _progress(progress, 'checking_host_dependencies', 'Reading installed Homebrew versions…',
                        detail=' '.join(inventory_command))
        rc, text = await _run_command(inventory_command, env=env)
        if rc:
            raise HostPrerequisiteError('Cannot read installed Homebrew formulae; no installation started.',
                                        code='package_preflight_failed')
        installed: dict[str, tuple[str, ...]] = {}
        for line in text.splitlines():
            if not line.strip():
                continue
            fields = line.split()
            name = canonical_formula_name(fields[0])
            if (len(fields) < 2 or name in installed
                    or any(not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+~:=-]{0,127}', version)
                           for version in fields[1:])):
                raise BrewPlanError('Installed Homebrew versions could not be read unambiguously.')
            installed[name] = tuple(fields[1:])
        dependency_command = [binary, 'deps', '--formula', '--union', '--full-name', '--include-build', *packages]
        await _progress(progress, 'checking_host_dependencies', 'Checking required Homebrew dependencies…',
                        detail=' '.join(dependency_command))
        rc, text = await _run_command(dependency_command, env=env, timeout=90)
        if rc:
            raise HostPrerequisiteError('Cannot verify the required Homebrew dependency list; no installation started.',
                                        code='package_preflight_failed')
        dependencies = {canonical_formula_name(line.strip()) for line in text.splitlines() if line.strip()}
        unknown = [entry.name for entry in entries if entry.name in installed and not entry.new_version]
        if unknown:
            metadata_command = [binary, 'info', '--json=v2', '--formula', *unknown]
            await _progress(progress, 'checking_host_dependencies', 'Reading planned dependency versions…',
                            detail=' '.join(metadata_command))
            rc, text = await _run_command(metadata_command, env=env, timeout=90)
            try:
                document = json.loads(text) if not rc else None
                formulae = document['formulae']
                if not isinstance(formulae, list) or len(formulae) != len(unknown):
                    raise ValueError('Unexpected formula metadata count.')
                versions = {}
                for formula in formulae:
                    name = canonical_formula_name(formula.get('full_name') or formula['name'])
                    stable, revision = formula['versions']['stable'], formula.get('revision', 0)
                    if (name not in unknown or name in versions or formula.get('pinned') is True
                            or not isinstance(stable, str) or not re.fullmatch(r'v?\d+(?:[.-]\d+)*', stable)
                            or type(revision) is not int or revision < 0):
                        raise ValueError('Unverifiable or pinned dependency metadata.')
                    versions[name] = stable + (f'_{revision}' if revision else '')
                if set(versions) != set(unknown):
                    raise ValueError('Missing dependency metadata.')
            except (ValueError, KeyError, TypeError, AttributeError) as exc:
                raise HostPrerequisiteError('Cannot verify the planned Homebrew dependency versions; '
                                            'no installation started. Check brew info for ' + ', '.join(unknown) + '.',
                                            code='package_preflight_failed') from exc
            entries = tuple(replace(entry, new_version=versions[entry.name]) if entry.name in versions else entry
                            for entry in entries)
        facts = [{'name': entry.name, 'action': 'upgrade' if entry.name in installed else 'install',
                  'installed_versions': list(installed.get(entry.name, ())), 'target_version': entry.new_version}
                 for entry in entries]
        upgrades = validate_brew_plan(entries, installed, packages, dependencies)
        for fact in facts:
            before = ', '.join(fact['installed_versions']) or 'not installed'
            after = fact['target_version'] or 'version selected by Homebrew'
            await _progress(progress, 'checking_host_dependencies', 'Verified Homebrew planned action',
                            detail=f"{fact['action']} {fact['name']}: {before} -> {after}")
        return upgrades, facts
    except BrewPlanError as exc:
        error = HostPrerequisiteError('Homebrew prerequisite plan could not be accepted: ' + str(exc)
                                      + ' No packages were changed.', code='package_plan_unverified')
        error.planned_formulae = facts
        raise error from exc
    except HostPrerequisiteError as exc:
        exc.planned_formulae = facts
        raise


def package_selection(manager: str, missing: list[str], arch: str) -> list[str]:
    maps = {
        'brew': {'limactl': 'lima', 'ssh': 'openssh', 'ssh-keygen': 'openssh',
                 'qemu-system-x86_64': 'qemu', 'qemu-system-aarch64': 'qemu', 'qemu-img': 'qemu',
                 'qemu-system-mips': 'qemu', 'qemu-system-mipsel': 'qemu',
                 'qemu-system-mips64': 'qemu', 'qemu-system-mips64el': 'qemu',
                 'debugfs': 'e2fsprogs', 'e2fsck': 'e2fsprogs', 'resize2fs': 'e2fsprogs', 'swtpm': 'swtpm',
                 'qemu-firmware-aarch64': 'qemu', 'qemu-firmware-x86_64': 'qemu',
                 'lima-additional-guestagents': 'lima-additional-guestagents'},
        'dnf': {'ssh': 'openssh-clients', 'ssh-keygen': 'openssh-clients',
                'qemu-system-x86_64': 'qemu-system-x86-core', 'qemu-system-aarch64': 'qemu-system-aarch64-core', 'qemu-img': 'qemu-img',
                'qemu-system-mips': 'qemu-system-mips-core', 'qemu-system-mipsel': 'qemu-system-mips-core',
                'qemu-system-mips64': 'qemu-system-mips-core', 'qemu-system-mips64el': 'qemu-system-mips-core',
                'debugfs': 'e2fsprogs', 'e2fsck': 'e2fsprogs', 'resize2fs': 'e2fsprogs', 'swtpm': 'swtpm',
                'qemu-firmware-aarch64': 'edk2-aarch64', 'qemu-firmware-x86_64': 'edk2-ovmf'},
        'apt-get': {'ssh': 'openssh-client', 'ssh-keygen': 'openssh-client',
                    'qemu-system-x86_64': 'qemu-system-x86', 'qemu-system-aarch64': 'qemu-system-arm', 'qemu-img': 'qemu-utils',
                    'qemu-system-mips': 'qemu-system-mips', 'qemu-system-mipsel': 'qemu-system-mips',
                    'qemu-system-mips64': 'qemu-system-mips', 'qemu-system-mips64el': 'qemu-system-mips',
                    'debugfs': 'e2fsprogs', 'e2fsck': 'e2fsprogs', 'resize2fs': 'e2fsprogs', 'swtpm': 'swtpm',
                    'qemu-firmware-aarch64': 'qemu-efi-aarch64', 'qemu-firmware-x86_64': 'ovmf'},
    }
    mapping = maps.get(manager, {})
    unsupported = [name for name in missing if name not in mapping]
    if unsupported:
        linux_hint = (' On Linux, install Lima 2.x using its official binary/package method, Nix, '
                      'or Linuxbrew/Homebrew and ensure limactl is on PATH.') if platform.system() == 'Linux' else ''
        if any(name in {'limactl', 'lima-additional-guestagents'} for name in unsupported):
            hint = 'Install Lima and matching additional guest agents using a supported Lima installation method.' + linux_hint
        else:
            hint = 'Install the missing host tools using a package supported by this host distribution.'
        raise HostPrerequisiteError(f'{manager} has no supported automatic mapping for {", ".join(unsupported)}. '
                                    + hint + ' Then retry. No guest rebuild or network change is needed.')
    return list(dict.fromkeys(mapping[name] for name in missing))


def _has_interactive_terminal() -> bool:
    try:
        if not all(os.isatty(fd) for fd in (0, 1, 2)):
            return False
        # An ampersand launch can retain a TTY while belonging to a background
        # process group. Reading its terminal would suspend it with SIGTTIN.
        return os.name != 'posix' or os.tcgetpgrp(0) == os.getpgrp()
    except OSError:
        return False


async def _install(missing: list[str], architecture: str | None, lima_version: str, *, progress=None,
                   interactive: bool = False, scope: str = 'workspace_backend') -> None:
    global _TERMINAL_AUTH_ATTEMPTED
    candidates = ('brew', 'dnf', 'apt-get') if platform.system() == 'Darwin' else ('dnf', 'apt-get', 'brew')
    available = [(name, discover_binary(name)) for name in candidates]
    # On Linux, Lima itself needs an available supported Lima package manager,
    # not the unrelated graphics packages that may share its short name.
    if any(name in missing for name in ('limactl', 'lima-additional-guestagents')):
        available.sort(key=lambda pair: pair[0] != 'brew')
    manager, binary = next(((name, path) for name, path in available if path), ('', None))
    if not binary:
        linux_hint = (' For Lima on Linux, use its official binary/package method, Nix, or Linuxbrew/Homebrew; '
                      'HarnessyXO will discover limactl from standard system, Linuxbrew, or ~/.local/bin paths.') \
                     if platform.system() == 'Linux' else ''
        raise HostPrerequisiteError('Missing host prerequisites: ' + ', '.join(missing) +
                                    '. No supported package manager was found (Homebrew, dnf, apt-get).' + linux_hint +
                                    ' Install the selected backend prerequisites, then retry.', code='package_manager_unavailable')
    packages = package_selection(manager, missing, architecture or canonical_arch(platform.machine()))
    env = dict(os.environ, PATH=repaired_path(), LC_ALL='C', LANG='C',
               HOMEBREW_NO_AUTO_UPDATE='1', HOMEBREW_NO_INSTALL_UPGRADE='1',
               HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK='1', HOMEBREW_NO_INSTALL_CLEANUP='1',
               HOMEBREW_NO_ANALYTICS='1', HOMEBREW_NO_ASK='1', HOMEBREW_NO_COLOR='1',
               HOMEBREW_NO_EMOJI='1', HOMEBREW_NO_ENV_HINTS='1',
               DEBIAN_FRONTEND='noninteractive', NEEDRESTART_MODE='l')
    # Never let an inherited setting force an otherwise-disabled update.
    env.pop('HOMEBREW_FORCE_API_AUTO_UPDATE', None)
    prefix: list[str] = []
    retain_session = False
    if manager != 'brew' and getattr(os, 'geteuid', lambda: 1)() != 0:
        sudo = discover_binary('sudo')
        if not sudo:
            raise HostPrerequisiteError(f'Installing {", ".join(packages)} requires host administrator permission; sudo is unavailable. '
                                        f'Run {manager} install {" ".join(packages)} in an authorized host terminal, then retry.',
                                        code='administrator_authentication_required')
        # sudo timestamps are commonly scoped to a controlling terminal. Keep
        # every sudo child in this session, including -n verification and the
        # package transaction. Starting a new session here loses a successful
        # terminal authentication even though the password was just accepted.
        retain_session = True
        rc, _ = await _run_command([sudo, '-n', 'true'], env=env, retain_session=True)
        if rc:
            if interactive and not _TERMINAL_AUTH_ATTEMPTED and _has_interactive_terminal():
                _TERMINAL_AUTH_ATTEMPTED = True
                await _progress(progress, 'installing_host_dependencies',
                                'Host setup needs administrator access. Authenticate at the sudo prompt in this terminal.',
                                detail='Your password is handled by sudo directly; HarnessyXO does not read or store it.')
                rc, _ = await _run_command([sudo, '-v'], env=env, timeout=180,
                                           retain_session=True, terminal_input=True)
                if rc:
                    raise HostPrerequisiteError('Host administrator authentication did not complete. No packages were changed. '
                                                'Restart python3 run.py in an interactive host terminal to retry setup.',
                                                code='administrator_authentication_required')
                rc, _ = await _run_command([sudo, '-n', 'true'], env=env, retain_session=True)
            if rc:
                raise HostPrerequisiteError('Host setup needs administrator authentication in the launcher terminal. '
                                            'Run python3 run.py in an interactive host terminal to install missing prerequisites, '
                                            f'or run sudo {manager} install {" ".join(packages)} there. '
                                            'The browser cannot request or store your host password.',
                                            code='administrator_authentication_required')
        prefix = [sudo, '-n']
    if manager == 'brew':
        if 'lima-additional-guestagents' in packages and lima_version:
            rc, text = await _run_command([binary, 'info', '--json=v2', 'lima-additional-guestagents'], env=env)
            try:
                target = json.loads(text)['formulae'][0]['versions']['stable'] if not rc else ''
            except (ValueError, KeyError, IndexError, TypeError):
                target = ''
            if _version(str(target)) != lima_version:
                raise HostPrerequisiteError(f'The available additional guest-agent formula ({target or "unknown"}) '
                                            f'does not match installed Lima {lima_version}. Install a matching package explicitly; '
                                            'no Lima/QEMU upgrade or active-VM interruption was attempted.')
        install = [binary, 'install', '--formula', *packages]
        dry = [binary, 'install', '--dry-run', '--formula', *packages]
    elif manager == 'dnf':
        install = [*prefix, binary, '-y', '--setopt=install_weak_deps=False', 'install', *packages]
        dry = [*prefix, binary, '--assumeno', '--setopt=install_weak_deps=False', 'install', *packages]
    else:
        install = [*prefix, binary, '-y', '--no-upgrade', '--no-remove', 'install', *packages]
        dry = [*prefix, binary, '--simulate', '--no-upgrade', '--no-remove', 'install', *packages]
    await _progress(progress, 'checking_host_dependencies', 'Checking selected host package transaction…',
                    detail=' '.join(dry))
    rc, transaction = await _run_command(dry, env=env, timeout=90, retain_session=retain_session)
    if _OUTPUT_TRUNCATED in transaction:
        raise HostPrerequisiteError('The package-manager plan exceeded the output limit and could not be verified. '
                                    'No installation started. Inspect the package transaction in the host terminal.',
                                    code='package_plan_unverified')
    if manager == 'apt-get' and rc and re.search(
            r'Unable to locate package|has no installation candidate|404\s+Not Found|Failed to fetch', transaction, re.IGNORECASE):
        await _progress(progress, 'checking_host_dependencies', 'Refreshing host package indexes for missing prerequisites…')
        update_rc, update_text = await _run_command([*prefix, binary, 'update'], env=env, timeout=300,
                                                  retain_session=retain_session, progress=progress)
        if update_rc:
            raise HostPrerequisiteError('Host package indexes could not be refreshed; no packages were installed. '
                                        + update_text.strip()[-1500:], code='package_preflight_failed')
        rc, transaction = await _run_command(dry, env=env, timeout=90, retain_session=retain_session)
        if _OUTPUT_TRUNCATED in transaction:
            raise HostPrerequisiteError('The refreshed package-manager plan was truncated; no installation started.',
                                        code='package_plan_unverified')
    if rc and not (manager == 'dnf' and ('Operation aborted' in transaction or 'Transaction Summary' in transaction)):
        raise HostPrerequisiteError('Host package preflight failed; no installation started. ' + transaction.strip()[-1500:],
                                    code='package_preflight_failed')
    if manager != 'brew' and re.search(r'(?im)^\s*(?:Upgrading|Downgrading|Removing|Reinstalling|Obsoleting)\b|^Inst \S+ \[|^Remv ', transaction):
        raise HostPrerequisiteError('The package manager proposes changing installed packages, not just adding missing prerequisites. '
                                    'No automatic upgrade/removal was allowed. Resolve this in a maintenance window.\n' + transaction[-1500:],
                                    code='non_additive_transaction')
    planned_formulae: list[dict[str, Any]] = []
    vm_active: bool | None = None
    if manager == 'brew':
        try:
            upgrades, planned_formulae = await _review_brew_plan(binary, packages, transaction, env, progress=progress)
            if upgrades:
                names = ', '.join(entry.name for entry in upgrades)
                ps = discover_binary('ps')
                await _progress(progress, 'checking_host_dependencies', 'Checking active VMs before required dependency updates…',
                                detail=(str(ps) + ' -axo comm=') if ps else 'Host process inspection is unavailable.')
                try:
                    vm_active = await infrastructure_active()
                except HostPrerequisiteError as exc:
                    raise HostPrerequisiteError('Required Homebrew dependency updates: ' + names + '. '
                                                'Cannot verify that host VMs are stopped; no packages were changed. '
                                                'Check host process inspection, stop VMs, then retry python3 run.py.',
                                                code='dependency_update_requires_idle') from exc
                if vm_active:
                    raise HostPrerequisiteError('Installing ' + ', '.join(packages) + ' requires updating ' + names + '. '
                                                'Host VM processes are still running, so no packages were changed. '
                                                'Stop workspace and test VMs in Workspace Environment, then restart python3 run.py '
                                                'to install these required dependencies automatically. Guest reset is not needed.',
                                                code='dependency_update_requires_idle')
                await _progress(progress, 'installing_host_dependencies',
                                'Host VMs are stopped. Applying only the verified prerequisite dependency updates…', detail=names)
        except HostPrerequisiteError as exc:
            exc.planned_formulae = planned_formulae or getattr(exc, 'planned_formulae', ())
            exc.vm_infrastructure_active = vm_active
            _record_host_setup(scope, architecture, 'action_required', missing=missing, manager=manager, packages=packages,
                               error_code=exc.code, planned_formulae=exc.planned_formulae,
                               vm_infrastructure_active=vm_active)
            raise
    # Additions are safe with active guests; verified Homebrew dependency updates
    # additionally require idle VM infrastructure. Controllers are never replaced.
    _record_host_setup(scope, architecture, 'installing', missing=missing, manager=manager, packages=packages,
                       planned_formulae=planned_formulae, vm_infrastructure_active=vm_active)
    await _progress(progress, 'installing_host_dependencies', 'Installing selected host prerequisites…', detail=' '.join(install))
    rc, output = await _run_command(install, env=env, timeout=900, progress=progress,
                                  retain_session=retain_session)
    if rc:
        _record_host_setup(scope, architecture, 'failed', missing=missing, manager=manager, packages=packages,
                           returncode=rc, error_code='package_install_failed', planned_formulae=planned_formulae,
                           vm_infrastructure_active=vm_active)
        error = HostPrerequisiteError(f'Host prerequisite installation failed (exit {rc}). Verify package-manager permissions, '
                                      f'network access, and package availability, then retry.\n{output.strip()[-1800:]}',
                                      code='package_install_failed')
        error.returncode = rc
        error.planned_formulae = planned_formulae
        error.vm_infrastructure_active = vm_active
        raise error


async def _install_linux_lima(*, progress=None) -> dict[str, Any]:
    from .managed_lima import LIMA_VERSION, ManagedLimaError, install_managed_lima
    await _progress(progress, 'installing_host_dependencies', f'Preparing Lima {LIMA_VERSION} for this Linux account…',
                    detail='Downloading and verifying the official controller and matching guest agents. No administrator permission is needed.')
    try:
        result = await asyncio.to_thread(install_managed_lima)
    except ManagedLimaError as exc:
        if str(exc) == 'root_account_unsupported':
            raise HostPrerequisiteError('Lima cannot run as root. Start HarnessyXO with your normal user account.') from None
        raise HostPrerequisiteError('Automatic Linux Lima setup failed: ' + str(exc) +
                                    '. Check host internet access and your private HarnessyXO tools-cache permissions, then retry VM Start.') from None
    except Exception:
        raise HostPrerequisiteError('Automatic Linux Lima setup could not complete. Check host internet access and tools-cache permissions, then retry VM Start.') from None
    restore_host_tool_path()
    await _progress(progress, 'host_dependencies_ready', f'Lima {LIMA_VERSION} and matching guest agents are ready.',
                    cached=bool(result.get('cached')))
    return result


async def ensure_lima_controller(*, progress=None) -> str | None:
    """Linux launcher bootstrap; existing PATH installations retain priority."""
    restore_host_tool_path()
    existing = discover_binary('limactl')
    if existing is not None or platform.system() != 'Linux':
        return existing
    result = await _install_linux_lima(progress=progress)
    return str(result['binary'])


async def _ensure_workspace_prerequisites(config, *, vm_type: str | None = None, progress=None,
                                           allow_install: bool = True, interactive: bool = False) -> dict[str, Any]:
    if str(config.provider) != 'lima':
        raise HostPrerequisiteError(f'No host prerequisite installer exists for provider {config.provider}.',
                                    code='provider_unsupported')
    vm_type = vm_type or execution_mode(config.architecture, host_arch=platform.machine(), host_os=platform.system())[0]
    loop_key = id(asyncio.get_running_loop())
    async with _INSTALL_LOCKS.setdefault(loop_key, asyncio.Lock()):
        report: dict[str, Any] = {}
        try:
            await _progress(progress, 'checking_host_dependencies', 'Checking selected VM backend prerequisites…')
            report = await inspect_prerequisites(config.architecture, vm_type)
            _record_host_setup('workspace_backend', config.architecture, 'checking',
                               required=required_binaries(config.architecture, vm_type), missing=report['missing'])
            if report['missing']:
                if not allow_install:
                    raise HostPrerequisiteError('Missing host prerequisites: ' + ', '.join(report['missing']) +
                                                '. The VM is active; no packages were changed. Retry after work has stopped.',
                                                code='installation_disabled')
                if platform.system() == 'Linux' and 'limactl' in report['missing']:
                    # A private missing-controller install neither modifies a
                    # package-managed Lima nor interrupts existing VM processes.
                    await _install_linux_lima(progress=progress)
                    report = await inspect_prerequisites(config.architecture, vm_type)
                if report['missing']:
                    await _install(report['missing'], config.architecture, report['lima_version'], progress=progress,
                                   interactive=interactive)
                report = await inspect_prerequisites(config.architecture, vm_type)
                if report['missing']:
                    raise HostPrerequisiteError('Installation completed but verification still cannot find: ' + ', '.join(report['missing']) +
                                                '. Check host PATH, Lima/QEMU packages, UEFI firmware files and installation output. Guest data was not rebuilt.',
                                                code='post_install_verification_failed')
            await _progress(progress, 'host_dependencies_ready', 'Selected host prerequisites verified.')
            return report
        except HostPrerequisiteError as exc:
            _attach_report(exc, report)
            raise


async def _ensure_test_target_prerequisites(architecture: str | None = None, *, windows: bool = False,
                                             progress=None, allow_install: bool = True,
                                             interactive: bool = False) -> dict[str, Any]:
    """Install and verify target tools, including every architecture at startup.

    Interactive administrator authentication is opt-in for the terminal
    launcher only. Calls from Create/Start remain noninteractive and can still
    install with cached administrator permission or a user-owned Homebrew.
    """
    scope = 'all supported test-target' if architecture is None else 'selected test-target'
    loop_key = id(asyncio.get_running_loop())
    async with _INSTALL_LOCKS.setdefault(loop_key, asyncio.Lock()):
        report: dict[str, Any] = {}
        try:
            await _progress(progress, 'checking_host_dependencies', f'Checking {scope} host prerequisites…')
            report = await inspect_test_target_prerequisites(architecture, windows=windows)
            _record_host_setup('test_targets', architecture, 'checking',
                               required=test_target_required_binaries(architecture, windows=windows), missing=report['missing'])
            if report['missing']:
                if not allow_install:
                    raise HostPrerequisiteError('Missing test-target host prerequisites: ' + ', '.join(report['missing'])
                                                + '. Automatic package installation was disabled; no packages were changed.',
                                                code='installation_disabled')
                await _install(report['missing'], architecture, '',
                               progress=progress, interactive=interactive, scope='test_targets')
                report = await inspect_test_target_prerequisites(architecture, windows=windows)
                if report['missing'] or report['broken']:
                    details = []
                    if report['missing']:
                        details.append('Still missing: ' + ', '.join(report['missing']))
                    if report['broken']:
                        details.extend(report['broken'].values())
                    raise HostPrerequisiteError('Host package installation completed, but test-target verification failed. '
                                                + '\n'.join(details) + ' Check the installation output and host PATH, then retry.',
                                                code='post_install_verification_failed')
            # A failed optional-tool check must not prevent adding independent
            # missing dependencies. Keep the final failure visible and never
            # reinstall or accept a broken executable merely to report Ready.
            if report['broken']:
                raise HostPrerequisiteError('Installed test-target host tools failed verification: '
                                            + '\n'.join(report['broken'].values()), code='binary_verification_failed')
            await _progress(progress, 'host_dependencies_ready', f'{scope.capitalize()} host prerequisites verified.',
                            verified_binaries=len(report['versions']))
            return report
        except HostPrerequisiteError as exc:
            _attach_report(exc, report)
            raise


async def ensure_host_prerequisites(config, *, vm_type: str | None = None, progress=None,
                                    allow_install: bool = True, interactive: bool = False) -> dict[str, Any]:
    vm_type = vm_type or execution_mode(config.architecture, host_arch=platform.machine(), host_os=platform.system())[0]
    required = required_binaries(config.architecture, vm_type)
    _record_host_setup('workspace_backend', config.architecture, 'checking', required=required)
    try:
        report = await _ensure_workspace_prerequisites(config, vm_type=vm_type, progress=progress,
                                                       allow_install=allow_install, interactive=interactive)
    except Exception as exc:
        _record_host_setup('workspace_backend', config.architecture, 'failed', required=required,
                           missing=getattr(exc, 'missing_binaries', ()), broken=getattr(exc, 'broken_binaries', ()),
                           returncode=getattr(exc, 'returncode', None),
                           planned_formulae=getattr(exc, 'planned_formulae', ()),
                           vm_infrastructure_active=getattr(exc, 'vm_infrastructure_active', None),
                           error_code=exc.code if isinstance(exc, HostPrerequisiteError) else 'setup_failed')
        raise
    _record_host_setup('workspace_backend', config.architecture, 'ready', required=required)
    return report


async def ensure_test_target_prerequisites(architecture: str | None = None, *, windows: bool = False,
                                            progress=None, allow_install: bool = True,
                                            interactive: bool = False) -> dict[str, Any]:
    """Prepare all target kinds at startup, or recheck one target before Start."""
    required = test_target_required_binaries(architecture, windows=windows)
    _record_host_setup('test_targets', architecture, 'checking', required=required)
    try:
        report = await _ensure_test_target_prerequisites(architecture, windows=windows, progress=progress,
                                                         allow_install=allow_install, interactive=interactive)
    except Exception as exc:
        _record_host_setup('test_targets', architecture, 'failed', required=required,
                           missing=getattr(exc, 'missing_binaries', ()), broken=getattr(exc, 'broken_binaries', ()),
                           returncode=getattr(exc, 'returncode', None),
                           planned_formulae=getattr(exc, 'planned_formulae', ()),
                           vm_infrastructure_active=getattr(exc, 'vm_infrastructure_active', None),
                           error_code=exc.code if isinstance(exc, HostPrerequisiteError) else 'setup_failed')
        raise
    _record_host_setup('test_targets', architecture, 'ready', required=required)
    return report
