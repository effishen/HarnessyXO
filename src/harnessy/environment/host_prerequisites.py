"""Selected-backend host prerequisites. Shared by run.py and Create/Start.

Standard-library only. Uses fixed argv, repairs discovery before installing,
never changes a guest network policy or rebuilds a workspace. Package-manager
failures are actionable; privileges are never solicited through the browser.
"""
from __future__ import annotations
import asyncio
import json
import os
import platform
import re
import shutil
import signal
from pathlib import Path
from typing import Any

from .presets import canonical_arch, execution_mode

_KNOWN_BIN_DIRS = ('/opt/homebrew/bin', '/opt/homebrew/sbin', '/usr/local/bin',
                   '/usr/local/sbin', '/usr/bin', '/usr/sbin', '/bin', '/sbin',
                   '/home/linuxbrew/.linuxbrew/bin', '/opt/local/bin')
_INSTALL_LOCKS: dict[int, asyncio.Lock] = {}


class HostPrerequisiteError(RuntimeError):
    pass


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
        names += ['qemu-system-aarch64' if canonical_arch(architecture) == 'arm64' else 'qemu-system-x86_64', 'qemu-img']
    return tuple(names)


async def _progress(callback, phase: str, message: str, **meta) -> None:
    if callback:
        result = callback(phase, message, **meta)
        if asyncio.iscoroutine(result):
            await result


async def _run_command(argv: list[str], *, env: dict[str, str] | None = None,
                       timeout: float = 30, progress=None) -> tuple[int, str]:
    """Bounded fixed host-controller/package-manager invocation, no shell."""
    proc = await asyncio.create_subprocess_exec(
        *argv, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT, env=env, start_new_session=(os.name == 'posix'),
    )
    chunks: list[str] = []
    async def drain():
        pending = ''
        assert proc.stdout is not None
        while data := await proc.stdout.read(4096):
            text = data.decode('utf-8', errors='replace')
            chunks.append(text)
            if sum(map(len, chunks)) > 64000:
                chunks[:] = [''.join(chunks)[-48000:]]
            pending += text
            if progress and ('\n' in pending or len(pending) >= 500):
                await _progress(progress, 'installing_host_dependencies', 'Installing selected host prerequisites…',
                                detail=pending.strip()[-300:], progress_source='package_manager')
                pending = ''
        return await proc.wait()
    try:
        code = await asyncio.wait_for(drain(), timeout)
    except (asyncio.CancelledError, asyncio.TimeoutError):
        if proc.returncode is None:
            try:
                if os.name == 'posix':
                    os.killpg(proc.pid, signal.SIGTERM)
                else:
                    proc.terminate()
                await asyncio.wait_for(proc.wait(), 5)
            except (ProcessLookupError, asyncio.TimeoutError):
                if proc.returncode is None:
                    proc.kill()
                    await proc.wait()
        raise
    return int(code), ''.join(chunks)


def _version(text: str) -> str:
    match = re.search(r'\b(\d+\.\d+\.\d+)(?:[-+][\w.-]+)?', text)
    return match.group(1) if match else ''


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
    paths = {name: discover_binary(name) for name in required_binaries(architecture, vm_type)}
    missing = [name for name, path in paths.items() if not path]
    version = ''
    if paths.get('limactl'):
        rc, text = await _run_command([paths['limactl'], '--version'])
        if (rc and platform.system() == 'Linux' and os.geteuid() == 0
                and 'must not run as the root user' in text[:1024]):
            raise HostPrerequisiteError('Lima cannot run as root. Start HarnessyXO with your normal user account.')
        version = _version(text)
        if rc or not version or tuple(map(int, version.split('.'))) < (2, 0, 0):
            raise HostPrerequisiteError('Installed Lima must be version 2.0.0 or later and executable. '
                                        f'Observed: {text.strip()[:300] or "unknown"}. No automatic upgrade was attempted.')
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
                raise HostPrerequisiteError(f'{name} was found at {paths[name]} but cannot run: {text.strip()[-500:]}. '
                                            'Repair this installation; reinstalling or rebuilding the guest is not a PATH fix.')
    host_os = platform.system()
    host_arch = canonical_arch(platform.machine())
    kvm_present = host_os == 'Linux' and Path('/dev/kvm').exists()
    kvm_accessible = bool(kvm_present and os.access('/dev/kvm', os.R_OK | os.W_OK))
    return {'paths': paths, 'missing': missing, 'lima_version': version,
            'foreign_architecture': foreign, 'guest_agent': str(guest_agent) if guest_agent else None,
            'host_os': host_os, 'host_architecture': host_arch, 'vm_type': vm_type,
            # /dev/kvm is an accelerator, not a correctness prerequisite: Lima/QEMU
            # can still use software emulation when it is absent or inaccessible.
            'kvm_present': kvm_present, 'kvm_accessible': kvm_accessible}


async def infrastructure_active() -> bool:
    ps = discover_binary('ps')
    if not ps:
        raise HostPrerequisiteError('Cannot verify whether host VM infrastructure is active (ps is missing). '
                                    'Install prerequisites manually after checking active VMs.')
    rc, text = await _run_command([ps, '-axo', 'command='])
    if rc:
        raise HostPrerequisiteError('Could not inspect active host VM infrastructure. No packages were changed.')
    return any(re.search(r'(?:^|/|\s)(?:qemu-system-[\w-]+|limactl(?:\s+[^\n]*?)?\s+hostagent|lima-hostagent)(?:\s|$)', line)
               for line in text.splitlines())


def package_selection(manager: str, missing: list[str], arch: str) -> list[str]:
    maps = {
        'brew': {'limactl': 'lima', 'ssh': 'openssh', 'ssh-keygen': 'openssh',
                 'qemu-system-x86_64': 'qemu', 'qemu-system-aarch64': 'qemu', 'qemu-img': 'qemu',
                 'lima-additional-guestagents': 'lima-additional-guestagents'},
        'dnf': {'ssh': 'openssh-clients', 'ssh-keygen': 'openssh-clients',
                'qemu-system-x86_64': 'qemu-system-x86-core', 'qemu-system-aarch64': 'qemu-system-aarch64-core', 'qemu-img': 'qemu-img'},
        'apt-get': {'ssh': 'openssh-client', 'ssh-keygen': 'openssh-client',
                    'qemu-system-x86_64': 'qemu-system-x86', 'qemu-system-aarch64': 'qemu-system-arm', 'qemu-img': 'qemu-utils'},
    }
    mapping = maps.get(manager, {})
    unsupported = [name for name in missing if name not in mapping]
    if unsupported:
        linux_hint = (' On Linux, install Lima 2.x using its official binary/package method, Nix, '
                      'or Linuxbrew/Homebrew and ensure limactl is on PATH.') if platform.system() == 'Linux' else ''
        raise HostPrerequisiteError(f'{manager} has no supported automatic mapping for {", ".join(unsupported)}. '
                                    'Install Lima and matching additional guest agents using a supported Lima installation method.'
                                    + linux_hint + ' Then retry. No guest rebuild or network change is needed.')
    return list(dict.fromkeys(mapping[name] for name in missing))


async def _install(missing: list[str], architecture: str, lima_version: str, *, progress=None) -> None:
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
                                    ' Install the selected backend prerequisites, then retry.')
    packages = package_selection(manager, missing, architecture)
    env = dict(os.environ, PATH=repaired_path(), LC_ALL='C', LANG='C',
               HOMEBREW_NO_AUTO_UPDATE='1', HOMEBREW_NO_INSTALL_UPGRADE='1',
               HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK='1', HOMEBREW_NO_INSTALL_CLEANUP='1',
               HOMEBREW_NO_ANALYTICS='1', HOMEBREW_NO_ASK='1', DEBIAN_FRONTEND='noninteractive', NEEDRESTART_MODE='l')
    # Never let an inherited setting force an otherwise-disabled update.
    env.pop('HOMEBREW_FORCE_API_AUTO_UPDATE', None)
    prefix: list[str] = []
    if manager != 'brew' and getattr(os, 'geteuid', lambda: 1)() != 0:
        sudo = discover_binary('sudo')
        if not sudo:
            raise HostPrerequisiteError(f'Installing {", ".join(packages)} requires host administrator permission; sudo is unavailable. '
                                        f'Run {manager} install {" ".join(packages)} in an authorized host terminal, then retry.')
        rc, _ = await _run_command([sudo, '-n', 'true'], env=env)
        if rc:
            raise HostPrerequisiteError(f'Administrator permission is not available non-interactively. '
                                        f'Run sudo {manager} install {" ".join(packages)} in your host terminal, then retry. '
                                        'HarnessyXO will not request or store your password.')
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
                    detail=' '.join(install))
    rc, transaction = await _run_command(dry, env=env, timeout=90)
    if rc and not (manager == 'dnf' and ('Operation aborted' in transaction or 'Transaction Summary' in transaction)):
        raise HostPrerequisiteError('Host package preflight failed; no installation started. ' + transaction.strip()[-1500:])
    if re.search(r'(?im)^\s*(?:Upgrading|Downgrading|Removing|Reinstalling|Obsoleting)\b|^Inst \S+ \[|^Remv ', transaction):
        raise HostPrerequisiteError('The package manager proposes changing installed packages, not just adding missing prerequisites. '
                                    'No automatic upgrade/removal was allowed. Resolve this in a maintenance window.\n' + transaction[-1500:])
    # Homebrew's dry-run can list already-installed dependencies as new versions
    # without an "Upgrading" heading. Refuse every such installed intersection.
    if manager == 'brew':
        rc, installed = await _run_command([binary, 'list', '--formula', '--versions'], env=env)
        if rc:
            raise HostPrerequisiteError('Cannot verify installed Homebrew formulae before the transaction; no changes were made.')
        for line in installed.splitlines():
            name = line.split()[0] if line.split() else ''
            if name and re.search(r'(?<![\w@.+/-])' + re.escape(name) + r'(?![\w@.+/-])', transaction):
                raise HostPrerequisiteError(f'The install plan touches installed formula {name}; resolve dependencies explicitly before retrying. '
                                            'No automatic upgrades were performed.')
    if await infrastructure_active():
        raise HostPrerequisiteError('Host VM infrastructure is active. Prerequisite installation was deferred without stopping it. '
                                    'Finish/stop those VMs during a maintenance window, then retry.')
    await _progress(progress, 'installing_host_dependencies', 'Installing selected host prerequisites…', detail=', '.join(packages))
    rc, output = await _run_command(install, env=env, timeout=900, progress=progress)
    if rc:
        raise HostPrerequisiteError(f'Host prerequisite installation failed (exit {rc}). Verify package-manager permissions, '
                                    f'network access, and package availability, then retry.\n{output.strip()[-1800:]}')


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


async def ensure_host_prerequisites(config, *, vm_type: str | None = None, progress=None,
                                    allow_install: bool = True) -> dict[str, Any]:
    if str(config.provider) != 'lima':
        raise HostPrerequisiteError(f'No host prerequisite installer exists for provider {config.provider}.')
    vm_type = vm_type or execution_mode(config.architecture, host_arch=platform.machine(), host_os=platform.system())[0]
    loop_key = id(asyncio.get_running_loop())
    async with _INSTALL_LOCKS.setdefault(loop_key, asyncio.Lock()):
        await _progress(progress, 'checking_host_dependencies', 'Checking selected VM backend prerequisites…')
        report = await inspect_prerequisites(config.architecture, vm_type)
        if report['missing']:
            if not allow_install:
                raise HostPrerequisiteError('Missing host prerequisites: ' + ', '.join(report['missing']) +
                                            '. The VM is active; no packages were changed. Retry after work has stopped.')
            if platform.system() == 'Linux' and 'limactl' in report['missing']:
                # A private missing-controller install neither modifies a
                # package-managed Lima nor interrupts existing VM processes.
                await _install_linux_lima(progress=progress)
                report = await inspect_prerequisites(config.architecture, vm_type)
            if report['missing'] and await infrastructure_active():
                raise HostPrerequisiteError('Host VM infrastructure is active; missing prerequisites (' +
                                            ', '.join(report['missing']) + ') were not installed or upgraded. Retry during maintenance.')
            if report['missing']:
                await _install(report['missing'], config.architecture, report['lima_version'], progress=progress)
            report = await inspect_prerequisites(config.architecture, vm_type)
            if report['missing']:
                raise HostPrerequisiteError('Installation completed but verification still cannot find: ' + ', '.join(report['missing']) +
                                            '. Check host PATH, Lima package versions and installation output. Guest data was not rebuilt.')
        await _progress(progress, 'host_dependencies_ready', 'Selected host prerequisites verified.')
        return report
