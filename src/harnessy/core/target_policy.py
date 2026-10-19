"""Canonical target action permissions, independent of the global tool gate.

Command categories describe best-effort text checks. They do not turn an SSH
account, an interpreter or a shell into an operating-system isolation boundary.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any
from .project_access import normalize_project_access


TARGET_ACCESS_MODE_LABELS = {
    'full': 'Allow Full Unrestricted Access',
    'selected': 'Allow Only Selected Actions',
}
TARGET_ACCESS_MODES = frozenset(TARGET_ACCESS_MODE_LABELS)
TARGET_PERMISSION_LABELS = {'off': 'Off', 'ask': 'Ask', 'on': 'On'}
TARGET_PERMISSIONS = frozenset(TARGET_PERMISSION_LABELS)

TARGET_ACTION_LABELS = {
    'allow_status': 'Check status, identity and test-root access',
    'allow_list': 'List files',
    'allow_exec': 'Run commands',
    'allow_copy_to': 'Copy files to the target',
    'allow_copy_from': 'Copy files from the target',
    'vm_start': 'Start this test VM',
    'vm_stop': 'Stop this test VM',
    'vm_snapshot': 'Create test VM snapshots',
    'vm_restore': 'Restore test VM snapshots',
    'exec_privilege': 'Privilege escalation',
    'exec_packages': 'Install or manage packages',
    'exec_services': 'Manage services',
    'exec_disks_mounts': 'Manage disks and mounts',
    'exec_power': 'Power controls',
    'exec_firewall': 'Manage firewalls',
    'exec_users_groups': 'Manage users and groups',
    'exec_process_isolation': 'Process isolation',
    'exec_remote_network': 'Remote access and network tools',
    'exec_system_paths': 'Reference system paths in commands',
    'outside_test_root': 'Use paths outside the test root',
}
TARGET_ACTIONS = tuple(TARGET_ACTION_LABELS)
TARGET_ACTION_GROUPS = (
    ('Target tools', TARGET_ACTIONS[:5]),
    ('Test VM controls', TARGET_ACTIONS[5:9]),
    ('Command categories and paths', TARGET_ACTIONS[9:]),
)

# Keep command categories here so storage, the editor and the execution broker
# share one vocabulary without circular imports. Examples cover common Linux,
# OpenWrt, macOS and Windows tools; arbitrary shell code cannot be classified
# completely by command-name matching.
TARGET_COMMAND_RULES: tuple[tuple[str, str, str, str], ...] = (
    ('exec_privilege', 'Privilege escalation', r'sudo|su|doas|pkexec|runas(?:\.exe)?',
     'sudo, su, doas, pkexec, runas'),
    ('exec_packages', 'Packages', r'apt(?:-get)?|dpkg|dnf|yum|rpm|apk|pacman|opkg|brew|pip(?:[23](?:\.\d+)?)?|npm|pnpm|yarn|winget(?:\.exe)?|choco(?:\.exe)?|scoop|Install-Package',
     'apt, apt-get, dpkg, dnf, yum, rpm, apk, pacman, opkg, brew, pip, pip3, npm, pnpm, yarn, winget, choco, scoop, Install-Package'),
    ('exec_services', 'Services', r'systemctl|service|rc-service|(?:/etc/)?init\.d/[A-Za-z0-9_.-]+|Start-Service|Stop-Service|Restart-Service|Set-Service|sc(?:\.exe)?',
     'systemctl, service, rc-service, /etc/init.d/*, Start-Service, Stop-Service, Restart-Service, Set-Service, sc.exe'),
    ('exec_disks_mounts', 'Disks and mounts', r'mount|umount|fdisk|sfdisk|parted|mkfs(?:\.[A-Za-z0-9_-]+)?|dd|diskpart(?:\.exe)?|Format-Volume|Initialize-Disk|Clear-Disk|New-Partition|Remove-Partition',
     'mount, umount, fdisk, sfdisk, parted, mkfs, mkfs.*, dd, diskpart, Format-Volume, Initialize-Disk, Clear-Disk, New-Partition, Remove-Partition'),
    ('exec_power', 'Power controls', r'reboot|shutdown(?:\.exe)?|halt|poweroff|Restart-Computer|Stop-Computer',
     'reboot, shutdown, halt, poweroff, Restart-Computer, Stop-Computer'),
    ('exec_firewall', 'Firewalls', r'iptables|ip6tables|nft|pfctl|New-NetFirewallRule|Set-NetFirewallRule|Remove-NetFirewallRule|Set-NetFirewallProfile',
     'iptables, ip6tables, nft, pfctl, New-NetFirewallRule, Set-NetFirewallRule, Remove-NetFirewallRule, Set-NetFirewallProfile'),
    ('exec_users_groups', 'Users and groups', r'useradd|userdel|usermod|groupadd|groupdel|passwd|New-LocalUser|Set-LocalUser|Remove-LocalUser|New-LocalGroup|Remove-LocalGroup|Add-LocalGroupMember|Remove-LocalGroupMember|net(?:\.exe)?',
     'useradd, userdel, usermod, groupadd, groupdel, passwd, New-LocalUser, Set-LocalUser, Remove-LocalUser, New-LocalGroup, Remove-LocalGroup, Add-LocalGroupMember, Remove-LocalGroupMember, net.exe'),
    ('exec_process_isolation', 'Process isolation', r'chroot|nsenter', 'chroot, nsenter'),
    ('exec_remote_network', 'Remote access and network tools', r'ssh|scp|sftp|telnet|nc|netcat|socat|nmap|Enter-PSSession|New-PSSession|Invoke-Command',
     'ssh, scp, sftp, telnet, nc, netcat, socat, nmap, Enter-PSSession, New-PSSession, Invoke-Command'),
)
TARGET_PROTECTED_PATHS = (
    '/etc', '/root', '/boot', '/sys', '/proc', '/run', '/var/lib', '/var/run', '/home',
)


def _permission(value: Any) -> str:
    return value if isinstance(value, str) and value in TARGET_PERMISSIONS else 'off'


def normalize_target_policy(
    policy: Mapping[str, Any] | None, *, approval_mode: str = 'ask', managed_vm: bool = False,
) -> dict[str, Any]:
    """Return a complete canonical policy, migrating legacy access conservatively.

    An explicit new policy never inherits grants for omitted/invalid actions.
    Legacy targets remain selected; their saved false booleans and the old SSH
    command restrictions survive loading and unrelated target edits.
    """
    source = policy if isinstance(policy, Mapping) else {}
    project_scope = normalize_project_access(policy)
    if 'access_mode' in source or 'actions' in source:
        mode = source.get('access_mode')
        mode = mode if isinstance(mode, str) and mode in TARGET_ACCESS_MODES else 'selected'
        incoming = source.get('actions')
        incoming = incoming if isinstance(incoming, Mapping) else {}
        actions = {
            action: _permission(incoming.get(action))
            for action in TARGET_ACTIONS
        }
        return {'access_mode': mode, 'actions': actions, **project_scope}

    protected = 'on' if approval_mode == 'on' else 'ask'
    actions = {action: protected for action in TARGET_ACTIONS[:9]}
    actions['allow_status'] = 'on'
    actions['allow_list'] = 'on'
    for action in ('allow_exec', 'allow_list', 'allow_copy_to', 'allow_copy_from'):
        if not bool(source.get(action, True)):
            actions[action] = 'off'
    actions.update({action: 'on' if managed_vm else 'off' for action in TARGET_ACTIONS[9:-1]})
    actions['outside_test_root'] = 'off'
    return {'access_mode': 'selected', 'actions': actions, **project_scope}


def target_access_mode(policy: Mapping[str, Any] | None) -> str:
    """Return the canonical mode without granting access to malformed input."""
    return 'full' if isinstance(policy, Mapping) and policy.get('access_mode') == 'full' else 'selected'


def target_action_permission(
    policy: Mapping[str, Any] | None, action: str, *, approval_mode: str = 'ask',
    managed_vm: bool = False,
) -> str:
    if not isinstance(action, str) or action not in TARGET_ACTION_LABELS:
        return 'off'
    normalized = normalize_target_policy(policy, approval_mode=approval_mode, managed_vm=managed_vm)
    return 'on' if normalized['access_mode'] == 'full' else normalized['actions'][action]


def merge_target_permissions(permissions: Iterable[str]) -> str:
    """Combine required actions; an Off or invalid permission always wins."""
    states = {_permission(permission) for permission in permissions}
    return 'off' if 'off' in states else 'ask' if 'ask' in states else 'on'
