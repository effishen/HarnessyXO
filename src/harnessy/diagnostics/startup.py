"""Reviewed launcher and REA storage receipts, independent of application data."""
from __future__ import annotations

from pathlib import PurePosixPath
import re
from typing import Any

STARTUP_EVENTS = frozenset({
    'launcher_source_update', 'launcher_rea_setup_start', 'launcher_rea_ready',
    'launcher_rea_setup_failed', 'launcher_kvm_setup', 'host_prerequisite_setup',
})
HOST_SETUP_SCOPES = frozenset({'launcher', 'test_targets', 'workspace_backend'})
HOST_SETUP_ARCHITECTURES = frozenset({'all', 'arm64', 'x86_64', 'mips', 'mipsel', 'mips64', 'mips64el'})
HOST_SETUP_STATUSES = frozenset({'checking', 'installing', 'ready', 'failed', 'action_required'})
HOST_SETUP_BINARIES = frozenset({
    'limactl', 'lima-additional-guestagents', 'ssh', 'ssh-keygen', 'qemu-img',
    'qemu-system-aarch64', 'qemu-system-x86_64', 'qemu-system-mips',
    'qemu-system-mipsel', 'qemu-system-mips64', 'qemu-system-mips64el',
    'debugfs', 'e2fsck', 'resize2fs', 'swtpm',
    'qemu-firmware-aarch64', 'qemu-firmware-x86_64',
})
HOST_SETUP_PACKAGES = frozenset({
    'lima', 'lima-additional-guestagents', 'openssh', 'openssh-client', 'openssh-clients',
    'qemu', 'qemu-system-x86', 'qemu-system-arm', 'qemu-system-mips', 'qemu-utils',
    'qemu-system-x86-core', 'qemu-system-aarch64-core', 'qemu-system-mips-core',
    'qemu-img', 'e2fsprogs', 'swtpm',
    'qemu-efi-aarch64', 'ovmf', 'edk2-aarch64', 'edk2-ovmf',
})
HOST_SETUP_ERROR_CODES = frozenset({
    'setup_failed', 'binary_verification_failed', 'installation_disabled',
    'administrator_authentication_required', 'package_preflight_failed',
    'non_additive_transaction', 'post_install_verification_failed',
    'package_install_failed', 'package_manager_unavailable', 'KVM_ACCESS_DENIED',
    'controller_version_unsupported',
    'package_plan_unverified', 'dependency_update_requires_idle', 'provider_unsupported',
})
HOST_ENVIRONMENT_PROVIDERS = frozenset({'lima', 'managed', 'openwrt'})
HOST_RUNTIME_BACKENDS = frozenset({'lima', 'qemu'})
KVM_SETUP_STATUSES = frozenset({'skipped', 'ready', 'relaunch', 'action_required', 'cancelled'})
KVM_SETUP_REASONS = frozenset({
    'KVM_NOT_REQUIRED', 'KVM_DEVICE_ABSENT', 'KVM_READY', 'KVM_GROUP_REFRESH_VERIFIED',
    'KVM_IDENTITY_UNSAFE', 'KVM_DEVICE_UNAVAILABLE', 'KVM_ACCOUNT_UNAVAILABLE',
    'KVM_DEVICE_GROUP_UNAVAILABLE', 'KVM_MEMBERSHIP_UNAVAILABLE', 'KVM_NONINTERACTIVE',
    'KVM_ACTIVE_GROUP_DENIED', 'KVM_TOOLS_UNAVAILABLE', 'KVM_SUDO_UNAVAILABLE',
    'KVM_GROUP_REFRESH_UNAVAILABLE', 'KVM_SUDO_DENIED', 'KVM_SETUP_CANCELLED',
    'KVM_SETUP_TIMEOUT', 'KVM_SETUP_FAILED', 'KVM_MEMBERSHIP_NOT_UPDATED',
    'KVM_GROUP_REFRESH_REQUIRED', 'KVM_GROUP_ADDED_REFRESH_REQUIRED', 'KVM_REFRESH_RETRY_STOPPED',
    'KVM_RELAUNCH_FAILED', 'KVM_IDENTITY_CHANGED',
})
UPDATE_STATES = frozenset({
    'zip_version_unrecognized', 'zip_local_changes', 'installation_changed',
    'unsupported_source_tree', 'zip_bootstrap_unavailable',
    'installation_lock_required', 'direct_start_ready', 'update_state_unsafe',
    'update_verification_required', 'windows_updates_unsupported',
    'repository_configuration_invalid', 'repository_metadata_unsafe',
    'repository_root_mismatch', 'branch_not_managed', 'repository_remote_mismatch',
    'updated', 'update_incomplete', 'local_changes', 'up_to_date',
    'history_not_fast_forward', 'check_unavailable', 'update_state_unavailable',
    'update_not_applied',
})
UPDATE_SUCCESS_STATES = frozenset({'updated', 'up_to_date', 'direct_start_ready'})
ARCHIVE_MISMATCH_REASONS = frozenset({
    'missing', 'unsafe_path', 'not_regular_file', 'content_size', 'content_hash',
    'unreadable', 'executable_mode', 'mode_repair_failed',
})
STORAGE_REASONS = frozenset({
    'missing', 'unreadable', 'symlink_redirect', 'wrong_type', 'wrong_owner',
    'writable_by_others', 'changed_during_validation', 'hard_link',
    'cannot_secure_permissions',
    'cannot_prepare_storage',
})
REA_ERROR_CODES = frozenset({
    'REA_STORAGE_UNSAFE', 'REA_NODE_UNSUPPORTED_PLATFORM', 'REA_NODE_SETTINGS_UNSAFE',
    'REA_NODE_DOWNLOAD_FAILED', 'REA_NODE_CHECKSUM_FAILED', 'REA_NODE_ARCHIVE_INVALID',
    'REA_NODE_VERIFY_FAILED', 'REA_NODE_LOCK_TIMEOUT', 'REA_NODE_INSTALL_FAILED',
    'REA_NODE_CLEANUP_FAILED', 'REA_NODE_BOOTSTRAP_CANCELLED',
    'REA_INSTALL_FAILED', 'REA_INSTALL_TIMEOUT', 'REA_INSTALL_VERIFY_FAILED',
    'REA_NODE_MISSING', 'REA_NODE_UNSUPPORTED', 'REA_NPM_MISSING', 'REA_NOT_INSTALLED',
    'REA_RUNTIME_MISSING', 'REA_VERSION_MISMATCH',
})
REA_STATES = frozenset({
    'ready', 'disabled', 'custom_command', 'storage_unsafe', 'install_failed',
    'not_installed', 'node_missing', 'node_unsupported', 'version_mismatch',
    'runtime_missing', 'runtime_invalid', 'unavailable',
})
_VERSION = re.compile(r'\d{1,6}\.\d{1,6}\.\d{1,6}')
_ROOT_FILES = frozenset({
    '.gitignore', '.gitattributes', 'README.md', 'FEATURES.md', 'CHANGELOG.md',
    'LICENSE', 'VERSION', 'run.py', 'harnessy_app.py', 'harnessy_update.py',
    'requirements.txt', 'run_harnessy.sh',
})
_STORAGE_COMPONENTS = frozenset({
    'settings_root', 'rea', 'rea/node', 'rea/runtime', 'rea/npm-cache',
    'rea/node/bin', 'rea/node/bin/node', 'rea/node/node.exe',
    'rea/node/harnessy-node.json', 'rea/node/lib', 'rea/node/lib/node_modules',
    'rea/node/lib/node_modules/npm', 'rea/node/lib/node_modules/npm/bin',
    'rea/node/lib/node_modules/npm/bin/npm-cli.js', 'rea/node/node_modules',
    'rea/node/node_modules/npm', 'rea/node/node_modules/npm/bin',
    'rea/node/node_modules/npm/bin/npm-cli.js', 'rea/runtime/node_modules',
    'rea/runtime/node_modules/rea-agents', 'rea/runtime/node_modules/rea-agents/scripts',
    'rea/runtime/node_modules/rea-agents/scripts/rea.mjs',
    'rea/runtime/node_modules/rea-agents/package.json',
    'rea/runtime/.harnessy-rea-runtime.json', 'rea/install.lock',
    'rea/node/descendant', 'rea/runtime/descendant', 'rea/npm-cache/descendant',
    'rea/runtime-install', 'rea/runtime-install/descendant',
    'rea/node-install', 'rea/node-install/descendant',
})


def _count(value: Any) -> bool:
    return type(value) is int and 0 <= value <= 2**63 - 1


def _application_path(value: Any) -> str | None:
    """Retain bounded tracked-source labels; reject host paths and traversal."""
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_./+@ -]{1,180}', value):
        return None
    if value.startswith('/') or any(part in {'', '.', '..'} for part in value.split('/')):
        return None
    if value in _ROOT_FILES or value in {'.github/workflows/release.yml', 'scripts/package_release.py'}:
        return value
    if value.startswith('src/harnessy/') and all(not part.startswith('.') for part in value.split('/')):
        return value
    if re.fullmatch(r'skills/(?:bug-fix|codebase-investigation|implementation|large-attachment-analysis|project-handover|refactor|release-packaging|web-research)/SKILL\.md', value):
        return value
    return None


def validate_archive_check(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    safe: dict[str, Any] = {}
    for key in ('expected_version', 'installed_version'):
        item = value.get(key)
        if isinstance(item, str) and (_VERSION.fullmatch(item) or
                key == 'installed_version' and item in {'missing', 'invalid', 'unreadable'}):
            safe[key] = item
    for key in ('mismatch_count', 'executable_repairs'):
        if _count(value.get(key)):
            safe[key] = value[key]
    if isinstance(value.get('only_executable_metadata'), bool):
        safe['only_executable_metadata'] = value['only_executable_metadata']
    if value.get('comparison') in ('release_tag', 'current_main'):
        safe['comparison'] = value['comparison']
    commit = value.get('verified_commit')
    if isinstance(commit, str) and re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', commit):
        safe['verified_commit'] = commit
    if isinstance(value.get('mismatches'), (list, tuple)):
        safe['mismatches'] = []
        for item in value['mismatches'][:8]:
            if not isinstance(item, dict):
                continue
            path = _application_path(item.get('path'))
            reason = item.get('reason')
            if path is not None and isinstance(reason, str) and reason in ARCHIVE_MISMATCH_REASONS:
                safe['mismatches'].append({'path': path, 'reason': reason})
    return safe


def _storage_component(value: Any) -> str | None:
    if value == '.':
        return 'settings_root'
    if not isinstance(value, str) or len(value) > 240:
        return None
    if value in _STORAGE_COMPONENTS:
        return value
    parts = value.split('/')
    if any(part in {'', '.', '..'} for part in parts) or PurePosixPath(value).is_absolute() or '\\' in value:
        return None
    if re.match(r'^rea/runtime-install-[0-9a-f]{32}(?:/|$)', value):
        return 'rea/runtime-install/descendant' if len(parts) > 2 else 'rea/runtime-install'
    if re.match(r'^rea/node-install-[A-Za-z0-9_-]{1,80}(?:/|$)', value):
        return 'rea/node-install/descendant' if len(parts) > 2 else 'rea/node-install'
    for parent in ('rea/node', 'rea/runtime', 'rea/npm-cache'):
        if value.startswith(parent + '/'):
            return parent + '/descendant'
    return None


def validate_storage_issue(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    component = _storage_component(value.get('component'))
    reason = value.get('reason')
    if component is None or not isinstance(reason, str) or reason not in STORAGE_REASONS:
        return {}
    safe: dict[str, Any] = {'component': component, 'reason': reason}
    mode = value.get('mode')
    if isinstance(mode, str) and re.fullmatch(r'[0-7]{4}', mode):
        safe['mode'] = mode
    if isinstance(value.get('owned_by_current_user'), bool):
        safe['owned_by_current_user'] = value['owned_by_current_user']
    return safe


def validate_startup_event(event: Any, value: Any) -> dict[str, Any] | None:
    if not isinstance(event, str) or event not in STARTUP_EVENTS or not isinstance(value, dict):
        return None
    safe: dict[str, Any] = {'event': event}
    if event == 'host_prerequisite_setup':
        # These receipts can be exported without content. Retain only fixed
        # tool/package identifiers, never process output or installer commands.
        for key, allowed in (('scope', HOST_SETUP_SCOPES),
                             ('architecture', HOST_SETUP_ARCHITECTURES),
                             ('status', HOST_SETUP_STATUSES)):
            item = value.get(key)
            if not isinstance(item, str) or item not in allowed:
                return None
            safe[key] = item
        for key, allowed in (('required_binaries', HOST_SETUP_BINARIES),
                             ('missing_binaries', HOST_SETUP_BINARIES),
                             ('broken_binaries', HOST_SETUP_BINARIES),
                             ('packages', HOST_SETUP_PACKAGES)):
            items = value.get(key)
            if isinstance(items, (list, tuple)):
                safe[key] = list(dict.fromkeys(item for item in items[:32]
                                               if isinstance(item, str) and item in allowed))
        for key, allowed in (('manager', {'apt-get', 'dnf', 'brew'}),
                             ('error_code', HOST_SETUP_ERROR_CODES)):
            item = value.get(key)
            if isinstance(item, str) and item in allowed:
                safe[key] = item
        if type(value.get('returncode')) is int and -(2**31) <= value['returncode'] < 2**31:
            safe['returncode'] = value['returncode']
        if type(value.get('checks_failed')) is int and 0 <= value['checks_failed'] <= 4096:
            safe['checks_failed'] = value['checks_failed']
        controller_version = value.get('controller_version')
        if isinstance(controller_version, str) and _VERSION.fullmatch(controller_version):
            safe['controller_version'] = controller_version
        if isinstance(value.get('vm_infrastructure_active'), bool):
            safe['vm_infrastructure_active'] = value['vm_infrastructure_active']
        # Package names and versions are operational facts. Never retain raw
        # installer output, argv, paths, URLs or arbitrary metadata here.
        planned = value.get('planned_formulae')
        if isinstance(planned, (list, tuple)):
            clean = []
            for item in planned[:256]:
                if (not isinstance(item, dict) or not isinstance(item.get('action'), str)
                        or item['action'] not in {'install', 'upgrade'}):
                    continue
                name = item.get('name')
                if (not isinstance(name, str) or len(name) > 160
                        or not re.fullmatch(r'[a-z0-9][a-z0-9@+_.-]*(?:/[a-z0-9][a-z0-9@+_.-]*){0,2}', name)):
                    continue
                versions = item.get('installed_versions')
                target = item.get('target_version', '')
                valid_version = lambda version: isinstance(version, str) and len(version) <= 128 and bool(
                    re.fullmatch(r'(?:v?\d|HEAD)[A-Za-z0-9._+~:=-]*', version))
                if (not isinstance(versions, (list, tuple)) or len(versions) > 8
                        or not all(valid_version(version) for version in versions)
                        or not (target == '' or valid_version(target))):
                    continue
                clean.append({'name': name, 'action': item['action'],
                              'installed_versions': list(versions), 'target_version': target})
            safe['planned_formulae'] = clean
    elif event == 'launcher_kvm_setup':
        for key, allowed in (('status', KVM_SETUP_STATUSES), ('reason_code', KVM_SETUP_REASONS)):
            if isinstance(value.get(key), str) and value[key] in allowed:
                safe[key] = value[key]
        if type(value.get('device_gid')) is int and 0 <= value['device_gid'] <= 2**32 - 1:
            safe['device_gid'] = value['device_gid']
        for key in ('kvm_present', 'kvm_accessible', 'device_group_active', 'saved_member',
                    'membership_changed', 'refresh_attempted'):
            if type(value.get(key)) is bool:
                safe[key] = value[key]
    elif event == 'launcher_source_update':
        state = value.get('state')
        if isinstance(state, str) and state in UPDATE_STATES:
            safe['state'] = state
        if isinstance(value.get('changed'), bool):
            safe['changed'] = value['changed']
        if isinstance(value.get('archive_check'), dict):
            safe['archive_check'] = validate_archive_check(value['archive_check'])
    else:
        version = value.get('version')
        if isinstance(version, str) and _VERSION.fullmatch(version):
            safe['version'] = version
        if isinstance(value.get('cached'), bool):
            safe['cached'] = value['cached']
        for key, allowed in (('error_code', REA_ERROR_CODES), ('status', REA_STATES)):
            item = value.get(key)
            if isinstance(item, str) and item in allowed:
                safe[key] = item
        if isinstance(value.get('storage_issue'), dict):
            safe['storage_issue'] = validate_storage_issue(value['storage_issue'])
        exception = value.get('exception_class')
        if isinstance(exception, str) and exception in {
            'OSError', 'PermissionError', 'ValueError', 'RuntimeError', 'TimeoutError',
            'CancelledError', 'UserStoreError', 'ReaError', 'ReaBootstrapError',
            'ReaStorageValidationError',
        }:
            safe['exception_class'] = exception
    return safe


def is_kvm_refresh_handoff(value: Any) -> bool:
    """Recognize only the reviewed receipt emitted before a group-refresh exec."""
    safe = validate_startup_event('launcher_kvm_setup', value)
    return bool(safe and safe.get('status') == 'relaunch' and safe.get('reason_code') in {
        'KVM_GROUP_REFRESH_REQUIRED', 'KVM_GROUP_ADDED_REFRESH_REQUIRED'})
