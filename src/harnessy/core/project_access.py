"""Exact project/chat membership for VM environments and external targets."""
from __future__ import annotations

import re
import uuid
from collections.abc import Mapping
from typing import Any

_PROJECT_ID_RE = re.compile(r'^(?:[0-9a-f]{32}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})$')


def canonical_project_id(value: Any) -> str:
    if not isinstance(value, str):
        return ''
    value = value.strip().lower()
    return str(uuid.UUID(value)) if _PROJECT_ID_RE.fullmatch(value) else ''


def normalize_project_access(source: Mapping[str, Any] | None) -> dict[str, Any]:
    """Missing fresh scope means all; malformed explicit scope grants nothing.

    Retain valid exact IDs even when currently in all-project mode so the
    selection editor can preserve its checkboxes. Parent/child relationships,
    names, public four-character labels and filesystem paths are irrelevant.
    """
    if source is not None and not isinstance(source, Mapping):
        return {'project_access': 'selected', 'allowed_project_ids': []}
    source = source if isinstance(source, Mapping) else {}
    if 'project_access' not in source and 'allowed_project_ids' not in source:
        return {'project_access': 'all', 'allowed_project_ids': []}
    mode = source.get('project_access')
    mode = mode.strip().lower() if isinstance(mode, str) else ''
    if mode not in {'all', 'selected'}:
        return {'project_access': 'selected', 'allowed_project_ids': []}
    raw_ids = source.get('allowed_project_ids', ())
    ids: list[str] = []
    if isinstance(raw_ids, (list, tuple, set)):
        for value in raw_ids:
            project_id = canonical_project_id(value)
            if project_id and project_id not in ids:
                ids.append(project_id)
    return {'project_access': mode, 'allowed_project_ids': ids}


def allows_project(source: Mapping[str, Any] | None, chat_id: Any) -> bool:
    project_id = canonical_project_id(chat_id)
    if not project_id:
        return False
    policy = normalize_project_access(source)
    return policy['project_access'] == 'all' or project_id in policy['allowed_project_ids']
