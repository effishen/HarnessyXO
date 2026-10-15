"""One-time terminal setup for the native Linux workspace VM's KVM group.

This module is standard-library only. It never starts a VM, changes device
permissions, launches the app as root, or executes the returned relaunch plan.
"""
from __future__ import annotations

from dataclasses import dataclass
import errno
import os
from pathlib import Path
import platform
import re
import shlex
import stat
import subprocess
import sys
from typing import Callable, Sequence

_DEVICE = '/dev/kvm'
_TOOLS = {'sudo': ('/usr/bin/sudo', '/bin/sudo'),
          'usermod': ('/usr/sbin/usermod', '/sbin/usermod'),
          'sg': ('/usr/bin/sg', '/bin/sg')}
SUDO_TIMEOUT_SECONDS = 180.0


@dataclass(frozen=True)
class KVMStartupPlan:
    status: str
    reason_code: str
    message: str = ''
    relaunch_argv: tuple[str, ...] = ()
    device_gid: int | None = None
    kvm_present: bool | None = None
    kvm_accessible: bool | None = None
    device_group_active: bool | None = None
    saved_member: bool | None = None
    membership_changed: bool = False
    refresh_attempted: bool = False

    def diagnostic_fields(self) -> dict:
        """Never log launch arguments, paths, account/group names or prose."""
        result = {'status': self.status, 'reason_code': self.reason_code,
                  'membership_changed': self.membership_changed, 'refresh_attempted': self.refresh_attempted}
        if type(self.device_gid) is int and 0 <= self.device_gid <= 2**32 - 1:
            result['device_gid'] = self.device_gid
        for name in ('kvm_present', 'kvm_accessible', 'device_group_active', 'saved_member'):
            if type(getattr(self, name)) is bool:
                result[name] = getattr(self, name)
        return result


def _canonical_arch(value: str) -> str:
    value = str(value or '').lower().strip()
    return {'aarch64': 'arm64', 'amd64': 'x86_64', 'x64': 'x86_64'}.get(value, value)


def _interactive_terminal() -> bool:
    try:
        return bool(sys.stdin.isatty() and sys.stdout.isatty() and sys.stderr.isatty())
    except (AttributeError, OSError):
        return False


def _trusted_system_binary(name: str) -> str | None:
    """Use fixed root-owned executables, never PATH or a workspace command."""
    for candidate in _TOOLS.get(name, ()):
        try:
            resolved = Path(candidate).resolve(strict=True)
            info = resolved.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                continue
            if not os.access(resolved, os.X_OK):
                continue
            original_chain = (Path(candidate), *Path(candidate).parents)
            if any((entry.lstat().st_uid != 0 or (not stat.S_ISLNK(entry.lstat().st_mode)
                    and entry.lstat().st_mode & 0o022)) for entry in original_chain):
                continue
            if any(parent.stat().st_uid != 0 or parent.stat().st_mode & 0o022 for parent in resolved.parents):
                continue
            # shadow's sg is commonly a symlink to newgrp; its argv[0] selects
            # noninteractive sg parsing. Validate the target, keep the alias.
            return candidate
        except (OSError, RuntimeError):
            continue
    return None


def _can_open_device() -> tuple[bool, int | None]:
    try:
        descriptor = os.open(_DEVICE, os.O_RDWR | getattr(os, 'O_CLOEXEC', 0)
                             | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0))
    except OSError as exc:
        return False, exc.errno
    else:
        try:
            os.close(descriptor)  # No ioctl, VM, or vCPU is created.
        except OSError as exc:
            return False, exc.errno
        return True, None


def _relaunch_argv(sg: str, python_executable: str, script_path: str | Path,
                   script_args: Sequence[str]) -> tuple[str, ...]:
    arguments = [python_executable, os.fspath(script_path), *script_args]
    if (not all(isinstance(value, str) and '\0' not in value for value in arguments)
            or not Path(arguments[0]).is_absolute() or not Path(arguments[1]).is_absolute()):
        raise ValueError('Relaunch requires absolute interpreter/script paths and text arguments')
    # SG's command is interpreted once by /bin/sh. Each original argument is a
    # single quoted shell word, including spaces, newlines and shell metacharacters.
    return sg, 'kvm', '-c', 'exec ' + shlex.join(arguments)


def prepare_kvm_startup(
    architecture: str, vm_type: str, *, python_executable: str,
    script_path: str | Path, script_args: Sequence[str] = (),
    refresh_attempted: bool = False, output: Callable[[str], None] = print,
) -> KVMStartupPlan:
    """Repair one missing saved KVM membership and return a group-refresh plan.

    The caller owns its install lock, one-time refresh marker and exec handoff.
    Sudo is attempted only in the original terminal, with inherited descriptors;
    this helper never captures, accepts, forwards or stores a password.
    """
    fields: dict = {'refresh_attempted': bool(refresh_attempted)}

    def result(status: str, code: str, message: str = '', argv: tuple[str, ...] = ()) -> KVMStartupPlan:
        return KVMStartupPlan(status, code, message, argv, **fields)

    if (platform.system() != 'Linux' or vm_type != 'qemu'
            or _canonical_arch(architecture) != _canonical_arch(platform.machine())):
        return result('skipped', 'KVM_NOT_REQUIRED')
    try:
        device = os.lstat(_DEVICE)
    except FileNotFoundError:
        fields['kvm_present'] = False
        return result('skipped', 'KVM_DEVICE_ABSENT')
    except OSError:
        return result('action_required', 'KVM_DEVICE_UNAVAILABLE', 'KVM device metadata is unavailable; check the host device setup.')
    fields.update(kvm_present=True, device_gid=device.st_gid)
    if not stat.S_ISCHR(device.st_mode):
        return result('action_required', 'KVM_DEVICE_UNAVAILABLE', '/dev/kvm must be a host character device; repair its host configuration manually.')
    uid, euid = os.getuid(), os.geteuid()
    if uid == 0 or uid != euid or os.getgid() != os.getegid():
        return result('action_required', 'KVM_IDENTITY_UNSAFE', 'Run HarnessyXO from your normal login account, without sudo or a changed effective identity.')
    accessible, error_number = _can_open_device()
    fields['kvm_accessible'] = accessible
    if accessible:
        return result('ready', 'KVM_GROUP_REFRESH_VERIFIED' if refresh_attempted else 'KVM_READY',
                      'KVM access: verified after group refresh.' if refresh_attempted else 'KVM access: ready.')
    try:
        fields['device_group_active'] = device.st_gid == os.getegid() or device.st_gid in os.getgroups()
    except OSError:
        return result('action_required', 'KVM_IDENTITY_UNSAFE', 'The current process groups could not be checked; restart from a fresh normal host login.')
    if error_number not in {errno.EACCES, errno.EPERM}:
        return result('action_required', 'KVM_DEVICE_UNAVAILABLE', 'The KVM device cannot be opened. Check the host driver/device configuration before retrying.')
    if refresh_attempted:
        return result('action_required', 'KVM_REFRESH_RETRY_STOPPED', 'KVM access is still denied after group refresh. Automatic setup will not repeat; check the host ACL/device policy.')
    if fields['device_group_active']:
        return result('action_required', 'KVM_ACTIVE_GROUP_DENIED', 'This process already has the KVM device group but access is denied. Check host ACLs and service/container device restrictions; adding the group again will not fix this.')
    try:
        import grp
        import pwd
        group = grp.getgrgid(device.st_gid)
        account = pwd.getpwuid(uid)
    except (KeyError, OSError, ImportError):
        return result('action_required', 'KVM_DEVICE_GROUP_UNAVAILABLE', 'The host account or KVM device group cannot be resolved; configure access manually.')
    # A device must never be used as a pretext to grant root/disk/sudo or another
    # powerful group. Automatic setup is limited to the standard KVM group.
    if device.st_uid != 0 or device.st_gid == 0 or group.gr_gid != device.st_gid or group.gr_name != 'kvm':
        return result('action_required', 'KVM_DEVICE_GROUP_UNAVAILABLE', 'Automatic setup requires a root-owned /dev/kvm device owned by the kvm group. Repair nonstandard host ownership manually.')
    if account.pw_uid != uid or account.pw_name == 'root' or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}\$?', account.pw_name):
        return result('action_required', 'KVM_ACCOUNT_UNAVAILABLE', 'The normal login account could not be verified for automatic KVM setup.')
    try:
        fields['saved_member'] = device.st_gid in os.getgrouplist(account.pw_name, account.pw_gid)
    except (OSError, KeyError, AttributeError):
        return result('action_required', 'KVM_MEMBERSHIP_UNAVAILABLE', 'Saved account groups could not be checked; configure KVM access in a normal host login.')
    if not _interactive_terminal():
        return result('action_required', 'KVM_NONINTERACTIVE', 'KVM setup needs the host terminal. Run python3 run.py interactively, or grant the service/container the kvm group and restart it.')
    sg = _trusted_system_binary('sg')
    if sg is None:
        return result('action_required', 'KVM_GROUP_REFRESH_UNAVAILABLE', 'The trusted system sg tool is unavailable. Refresh KVM membership by signing out/in, then restart HarnessyXO.')
    try:
        relaunch = _relaunch_argv(sg, python_executable, script_path, script_args)
    except (TypeError, ValueError):
        return result('action_required', 'KVM_GROUP_REFRESH_UNAVAILABLE', 'The startup interpreter/script arguments could not be verified for group refresh. Sign out/in and restart normally.')
    if not fields['saved_member']:
        sudo = _trusted_system_binary('sudo')
        usermod = _trusted_system_binary('usermod')
        if sudo is None:
            return result('action_required', 'KVM_SUDO_UNAVAILABLE', 'The trusted system sudo tool is unavailable. A host administrator must add your login account to the kvm group.')
        if usermod is None:
            return result('action_required', 'KVM_TOOLS_UNAVAILABLE', 'The trusted system usermod tool is unavailable. A host administrator must add your login account to the kvm group.')
        try:
            current = os.lstat(_DEVICE)
            if (current.st_dev, current.st_ino, current.st_rdev, current.st_uid, current.st_gid) != (
                    device.st_dev, device.st_ino, device.st_rdev, device.st_uid, device.st_gid):
                return result('action_required', 'KVM_DEVICE_UNAVAILABLE', 'The KVM device changed during setup. Check its host configuration before retrying.')
            output('KVM access needs one-time host setup. sudo will add your normal login account to the kvm group; its password prompt stays in this terminal.')
            completed = subprocess.run([sudo, '--', usermod, '-a', '-G', 'kvm', '--', account.pw_name],
                                       stdin=None, stdout=None, stderr=None, check=False, timeout=SUDO_TIMEOUT_SECONDS)
        except KeyboardInterrupt:
            return result('cancelled', 'KVM_SETUP_CANCELLED', 'Startup was stopped; run python3 run.py again when ready.')
        except subprocess.TimeoutExpired:
            return result('action_required', 'KVM_SETUP_TIMEOUT', 'KVM setup timed out. Verify your account groups before retrying; no automatic retry was made.')
        except OSError:
            return result('action_required', 'KVM_SETUP_FAILED', 'The host KVM setup command could not run. Check the terminal error or configure group access manually.')
        if completed.returncode in {-2, 130}:
            return result('cancelled', 'KVM_SETUP_CANCELLED', 'Startup was stopped; run python3 run.py again when ready.')
        if completed.returncode != 0:
            return result('action_required', 'KVM_SUDO_DENIED', 'KVM group setup did not succeed. The app may open; see the terminal error or ask a host administrator for access.')
        try:
            fields['saved_member'] = device.st_gid in os.getgrouplist(account.pw_name, account.pw_gid)
        except (OSError, KeyError, AttributeError):
            fields['saved_member'] = False
        if not fields['saved_member']:
            return result('action_required', 'KVM_MEMBERSHIP_NOT_UPDATED', 'The setup command completed, but saved KVM membership is not visible. Check the host account/group directory; automatic setup will not repeat this launch.')
        fields['membership_changed'] = True
    return result('relaunch', 'KVM_GROUP_ADDED_REFRESH_REQUIRED' if fields.get('membership_changed') else 'KVM_GROUP_REFRESH_REQUIRED',
                  'KVM membership is saved. Restarting this same Python launcher with refreshed group access.', relaunch)
