"""Authoritative source policy shared by VM commands and project terminals."""
from __future__ import annotations

import hashlib
import json
import re
import stat
from pathlib import Path
from typing import Any

_FOLDER = re.compile(r'^Project-[A-Za-z0-9]{4}$')
GUEST_CONSOLE_VIEW_ID = '__guest_console__'


def _identity(workspace, path: Path, label: str, project_id: str = '') -> dict[str, Any]:
    root = Path(workspace.root).resolve()
    path = Path(path)
    try:
        parts = path.relative_to(root).parts
    except ValueError as exc:
        raise ValueError('Project file source is outside this workspace.') from exc
    if not parts or parts[0] != 'Files' or len(parts) > 2:
        raise ValueError('Project views require canonical Files sources.')
    current = root
    for part in parts:
        current /= part
        metadata = current.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise ValueError('Project file source is missing, redirected, or not a directory: ' + label)
    return {'label': label, 'project_id': project_id, 'path': str(path),
            'device': metadata.st_dev, 'inode': metadata.st_ino}


def _revision(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def build_references_policy(workspace) -> dict[str, Any]:
    """Describe the workspace-wide, read-only human console input.

    This view has no Project origin and never inherits Project VM access,
    hierarchy or explicit grants. Planning validates the canonical directory
    without creating it or traversing its contents.
    """
    references = Path(workspace.root).resolve() / 'Files' / 'References'
    policy = {'namespace_version': 2, 'view_id': GUEST_CONSOLE_VIEW_ID,
              'project_id': GUEST_CONSOLE_VIEW_ID, 'references_folder': 'References',
              'references_root': str(references), 'readonly': True,
              'source_identities': (_identity(workspace, references, 'references'),)}
    policy['policy_revision'] = _revision(policy)
    return policy


def build_project_policy(workspace, chat_id: str) -> dict[str, Any]:
    """Describe one exact origin, automatic ancestors and direct RO grants.

    Planning does not create directories, follow source symlinks, copy files or
    inherit VM membership / another project's explicit access grants.
    """
    chat = workspace.get_chat(str(chat_id))
    if chat is None or chat.archived_at is not None:
        raise ValueError('The selected Project / Chat is unavailable or archived.')
    own = 'Project-' + str(chat.public_id)
    if not _FOLDER.fullmatch(own) or chat.active_root != own:
        raise ValueError('Project identity does not match its canonical source directory.')
    files = Path(workspace.root).resolve() / 'Files'
    project_root = files / own
    identities = [_identity(workspace, project_root, 'project', chat.id),
                  _identity(workspace, files / 'References', 'references')]
    ancestors, ancestor_by_id, nested_parts = [], {}, []
    for ancestor in workspace.ancestor_chats(chat.id):
        if ancestor.archived_at is not None:
            raise ValueError('A live ancestor Project / Chat is archived.')
        folder = 'Project-' + str(ancestor.public_id)
        if not _FOLDER.fullmatch(folder):
            raise ValueError('Invalid ancestor Project identity.')
        nested_parts.append(folder)
        row = {'chat_id': ancestor.id, 'project_chat_id': ancestor.public_id, 'folder': folder,
               'nested_path': '/'.join(nested_parts), 'title': ancestor.title, 'host_path': str(files / folder)}
        ancestors.append(row); ancestor_by_id[ancestor.id] = row
        identities.append(_identity(workspace, files / folder, row['nested_path'], ancestor.id))
    access = []
    for source in workspace.project_access_sources(chat.id):
        folder = 'Project-' + str(source.public_id)
        if not _FOLDER.fullmatch(folder):
            raise ValueError('Invalid Project Access source identity.')
        inherited = ancestor_by_id.get(source.id)
        access.append({'chat_id': source.id, 'project_chat_id': source.public_id, 'folder': folder,
                       'title': source.title, 'host_path': str(files / folder),
                       'files_path': f'Files/{own}/{inherited["nested_path"]}' if inherited else f'Files/{folder}',
                       'direct_mount': inherited is None, 'history_access': True,
                       'attachment_access': True, 'memory_access': True, 'task_state_access': True})
        if inherited is None:
            identities.append(_identity(workspace, files / folder, 'access:' + folder, source.id))
    policy = {'namespace_version': 2, 'project_id': chat.id, 'project_chat_id': chat.public_id,
              'writable_folder': own, 'folders': tuple(dict.fromkeys(
                  [own, *(row['folder'] for row in ancestors), *(row['folder'] for row in access if row['direct_mount'])])),
              'project_root': str(project_root), 'references_folder': 'References',
              'references_root': str(files / 'References'), 'ancestors': tuple(ancestors),
              'access_projects': tuple(access), 'source_identities': tuple(identities)}
    # Titles do not alter runtime identity or force an active namespace rebuild.
    fingerprint = {**policy, 'ancestors': [{k: v for k, v in row.items() if k != 'title'} for row in ancestors],
                   'access_projects': [{k: v for k, v in row.items() if k != 'title'} for row in access]}
    policy['policy_revision'] = _revision(fingerprint)
    return policy


def build_environment_plan(workspace, config) -> dict[str, Any]:
    chats = workspace.list_chats(archived=None)
    known = [{'project_id': chat.id, 'folder': 'Project-' + str(chat.public_id)} for chat in chats]
    projects, errors = [], []
    for chat in chats:
        if chat.archived_at is None and config.allows_project(chat.id):
            try:
                policy = build_project_policy(workspace, chat.id)
                projects.append({'project_id': chat.id, 'folder': policy['writable_folder'], 'policy': policy})
            except Exception as exc:
                errors.append({'project_id': chat.id, 'folder': 'Project-' + str(chat.public_id),
                               'state': 'error', 'error_code': 'FILE_VIEW_SOURCE_INVALID', 'detail': str(exc)[:500]})
    references_policy, references_error = None, None
    try:
        references_policy = build_references_policy(workspace)
    except Exception as exc:
        references_error = {'project_id': GUEST_CONSOLE_VIEW_ID, 'folder': 'References',
                            'state': 'error', 'error_code': 'FILE_VIEW_SOURCE_INVALID',
                            'detail': str(exc)[:500]}
    plan = {'schema': 1, 'environment_id': config.id, 'files_mode': config.files_mode,
            'model_enabled': config.enabled, 'projects': projects, 'known_projects': known,
            'errors': errors, 'references_policy': references_policy,
            'references_error': references_error}
    plan['revision'] = _revision({**plan, 'projects': [
        {'project_id': row['project_id'], 'policy_revision': row['policy']['policy_revision']} for row in projects]})
    return plan
