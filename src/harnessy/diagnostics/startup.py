"""Reviewed launcher and REA storage receipts, independent of application data."""
from __future__ import annotations

from pathlib import PurePosixPath
import re
from typing import Any

STARTUP_EVENTS = frozenset({
    'launcher_source_update', 'launcher_rea_setup_start', 'launcher_rea_ready',
    'launcher_rea_setup_failed',
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
    if event == 'launcher_source_update':
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
