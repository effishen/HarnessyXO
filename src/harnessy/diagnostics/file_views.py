"""Bounded mount-state receipts; no database, guest commands or source content."""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import re
import time
from typing import Any

_STATES = frozenset({'idle', 'requested', 'preparing', 'mounted', 'ready', 'pending',
                     'stopped', 'unsupported', 'failed', 'error', 'copy', 'revoked',
                     'unmounted', 'removed', 'retired', 'not_created', 'busy', 'unavailable'})
_CODES = frozenset({'', 'FILE_VIEW_PENDING', 'FILE_VIEW_BUSY', 'FILE_VIEW_UNSUPPORTED',
                    'FILE_VIEW_FAILED', 'FILE_VIEW_RECONCILE_FAILED', 'FILE_VIEW_RECONCILIATION_FAILED', 'FILE_VIEW_POLICY_CHANGED',
                    'FILE_VIEW_SOURCE_CHANGED', 'FILE_VIEW_TRANSPORT_FAILED',
                    'FILE_VIEW_SOURCE_INVALID', 'FILE_VIEW_STATUS_WRITE_FAILED',
                    'FILE_VIEW_REGISTRY_INVALID',
                    'VM_PROJECT_ACCESS_DENIED', 'VM_FILE_VIEW_PENDING', 'VM_FILE_VIEW_UNSUPPORTED',
                    'VM_FILE_VIEW_FAILED', 'VM_FILE_VIEW_SOURCE_CHANGED'})
_TRANSPORTS = frozenset({'lima', 'lima-bind', 'bind', 'mount_namespace', 'sshfs',
                         'sshfs-passive', 'copy', 'independent_copy', 'unsupported', 'none'})
_ID = re.compile(r'^[0-9a-f]{32}$|^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$')
_REV = re.compile(r'^[0-9a-f]{64}$')
_STAGES = _STATES | {'queued', 'planning', 'waiting_for_vm_operation', 'waiting_for_ready', 'reconciling', 'in_use'}
_BOOL_CAPS = ('live', 'readonly', 'copy', 'runtime_mounts', 'runtime_reconcile', 'reconcile',
              'project_isolation', 'readonly_enforced', 'project_views', 'live_mounts',
              'readonly_inputs', 'project_terminal', 'composite')


def project_status(value: Any) -> dict[str, Any]:
    """Project an untrusted persisted receipt through a fixed content-free schema."""
    if not isinstance(value, dict) or value.get('schema_version', value.get('schema')) != 1:
        raise ValueError('Invalid file-view receipt schema.')
    state = value.get('state')
    output: dict[str, Any] = {'state': state if isinstance(state, str) and state in _STATES else 'unavailable'}
    if isinstance(value.get('busy'), bool):
        output['busy'] = value['busy']
    stage = value.get('stage')
    if isinstance(stage, str) and stage in _STAGES:
        output['stage'] = stage
    for name in ('requested_revision', 'applied_revision'):
        revision = value.get(name)
        if isinstance(revision, str) and (_REV.fullmatch(revision) or revision == ''):
            output[name] = revision
    observed = value.get('updated_at')
    if isinstance(observed, (int, float)) and not isinstance(observed, bool) and math.isfinite(observed) and 0 <= observed <= 1e12:
        output['updated_at'] = observed
    code = value.get('error_code')
    if isinstance(code, str) and code in _CODES:
        output['error_code'] = code
    capabilities = value.get('capabilities')
    if isinstance(capabilities, dict):
        clean = {key: capabilities[key] for key in _BOOL_CAPS if isinstance(capabilities.get(key), bool)}
        transport = capabilities.get('transport')
        if isinstance(transport, str) and transport in _TRANSPORTS:
            clean['transport'] = transport
        modes = capabilities.get('supported_modes', capabilities.get('modes'))
        if isinstance(modes, (tuple, list)):
            clean['supported_modes'] = [mode for mode in ('live', 'readonly', 'copy') if mode in modes]
        output['capabilities'] = clean
    rows = value.get('projects')
    output['projects'] = []
    if isinstance(rows, list):
        for row in rows[:512]:
            if not isinstance(row, dict):
                continue
            project_id = row.get('project_id')
            state = row.get('state')
            if isinstance(project_id, str) and _ID.fullmatch(project_id):
                clean = {'project_id': project_id,
                         'state': state if isinstance(state, str) and state in _STATES else 'unavailable'}
                code = row.get('error_code')
                if isinstance(code, str) and code in _CODES:
                    clean['error_code'] = code
                revision = row.get('policy_revision')
                if isinstance(revision, str) and _REV.fullmatch(revision):
                    clean['policy_revision'] = revision
                output['projects'].append(clean)
        output['projects_limited'] = len(rows) > 512
    pending = value.get('pending_project_ids')
    output['pending_project_ids'] = [item for item in pending[:512]
        if isinstance(item, str) and _ID.fullmatch(item)] if isinstance(pending, list) else []
    output['pending_limited'] = isinstance(pending, list) and len(pending) > 512
    return output


def collect_file_view_diagnostics(latest: Path) -> dict[str, Any]:
    from .vm_logs import _discover_workspaces, _runtime_environments, _read_tail
    deadline = time.monotonic() + 3
    roots, discovery = _discover_workspaces(Path(latest).absolute(), deadline)
    output: dict[str, Any] = {'schema_version': 1, 'status': 'collected',
        'scope': 'persisted_runtime_observations', 'discovery': discovery,
        'limits': {'environments': 32, 'receipt_bytes': 256 * 1024, 'projects_per_environment': 512},
        'environments': []}
    limited = False
    for root, _origin in roots:
        if time.monotonic() >= deadline:
            limited = True
            break
        environments, truncated = _runtime_environments(root)
        limited = limited or truncated
        for environment_id, runtime_root in environments:
            if len(output['environments']) >= 32 or time.monotonic() >= deadline:
                limited = True
                break
            row = {'workspace_id': hashlib.sha256(str(root).encode()).hexdigest(),
                   'environment_id': environment_id}
            result = _read_tail(runtime_root / 'state' / 'file-views.json', 256 * 1024)
            row['receipt_status'] = result['status']
            if result['status'] == 'included':
                if result['truncated']:
                    row['receipt_status'] = 'limited'
                else:
                    try:
                        row.update(project_status(json.loads(result['data'])))
                    except (ValueError, RecursionError, UnicodeError):
                        row['receipt_status'] = 'invalid'
            output['environments'].append(row)
    output['limited'] = limited
    if not roots:
        output['status'] = 'no_workspaces'
    return output


def summary_lines(report: dict[str, Any]) -> str:
    rows = report.get('environments', [])
    noteworthy = [row for row in rows if row.get('state') in {'pending', 'busy', 'unsupported', 'failed', 'error'}]
    if not noteworthy:
        return '\nVM file views: see FILE_VIEWS.json for retained mount-state observations.\n'
    lines = ['\nVM file views needing attention (retained observations):']
    for row in noteworthy:
        lines.append('  VM ' + (row['environment_id'] or 'legacy') + ': ' + row['state']
                     + (' (' + row['error_code'] + ')' if row.get('error_code') else '')
                     + '; pending projects=' + str(len(row.get('pending_project_ids', []))))
    return '\n'.join(lines) + '\n'
