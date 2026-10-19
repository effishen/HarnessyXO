"""Process-owned lifecycle exclusion shared by agents, tools and VM controls.

VM reservations are independent. Workspace-wide callers still form a barrier
across every VM, for workspace removal and shared-project operations.
"""
from __future__ import annotations
from contextlib import contextmanager
from pathlib import Path
from threading import RLock
from typing import Callable
from uuid import uuid4

_LOCK = RLock()
_ACTIVE: dict[tuple[str, str], dict[str, str]] = {}
_CHANGING: dict[tuple[str, str], tuple[str, str]] = {}


def _key(root, environment_id: str | None = None) -> tuple[str, str]:
    return str(Path(root).expanduser().resolve()), str(environment_id) if environment_id is not None else '*'


def _overlaps(left: tuple[str, str], right: tuple[str, str]) -> bool:
    return left[0] == right[0] and (left[1] == '*' or right[1] == '*' or left[1] == right[1])


def active_work(root, *, environment_id: str | None = None) -> list[str]:
    key = _key(root, environment_id)
    with _LOCK:
        return [label for other, rows in _ACTIVE.items() if _overlaps(key, other) for label in rows.values()]


def acquire_activity(root, label: str, *, environment_id: str | None = None) -> Callable[[], None]:
    key, token = _key(root, environment_id), uuid4().hex
    with _LOCK:
        changing = next((value for other, value in _CHANGING.items() if _overlaps(key, other)), None)
        if changing is not None:
            description = changing[1]
            if description == 'network policy':
                raise RuntimeError('This VM network policy is being changed. Wait for that operation to finish before starting work.')
            raise RuntimeError(f'This VM environment is being changed ({description}). Wait for that operation to finish before starting work.')
        _ACTIVE.setdefault(key, {})[token] = label
    def release() -> None:
        with _LOCK:
            rows = _ACTIVE.get(key, {})
            rows.pop(token, None)
            if not rows:
                _ACTIVE.pop(key, None)
    return release


@contextmanager
def activity(root, label: str, *, environment_id: str | None = None):
    release = acquire_activity(root, label, environment_id=environment_id)
    try:
        yield
    finally:
        release()


def reserve_environment_change(root, description: str = 'environment', *,
                               environment_id: str | None = None) -> Callable[[], None]:
    key, token = _key(root, environment_id), uuid4().hex
    description = str(description or 'environment').strip() or 'environment'
    with _LOCK:
        current = next((value for other, value in _CHANGING.items() if _overlaps(key, other)), None)
        if current is not None:
            if current[1] == 'network policy':
                raise RuntimeError('A network-policy change is already in progress for this VM.')
            raise RuntimeError(f'A VM environment change is already in progress ({current[1]}).')
        labels = active_work(root, environment_id=environment_id)
        if labels:
            raise RuntimeError('Cannot change ' + description + ' while this VM has active work: ' +
                               ', '.join(labels[:4]) + '. Stop or finish that work first; nothing was interrupted.')
        _CHANGING[key] = (token, description)
    def release() -> None:
        with _LOCK:
            current = _CHANGING.get(key)
            if current is not None and current[0] == token:
                _CHANGING.pop(key, None)
    return release


def reserve_policy_change(root, *, environment_id: str | None = None) -> Callable[[], None]:
    return reserve_environment_change(root, 'network policy', environment_id=environment_id)
