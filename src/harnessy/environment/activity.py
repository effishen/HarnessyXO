"""Process-owned lifecycle exclusion shared by agents, tools and VM controls."""
from __future__ import annotations
from contextlib import contextmanager
from pathlib import Path
from threading import RLock
from typing import Callable
from uuid import uuid4

_LOCK = RLock()
_ACTIVE: dict[str, dict[str, str]] = {}
_CHANGING: dict[str, tuple[str, str]] = {}


def _key(root) -> str:
    return str(Path(root).expanduser().resolve())


def active_work(root) -> list[str]:
    with _LOCK:
        return list(_ACTIVE.get(_key(root), {}).values())


def acquire_activity(root, label: str) -> Callable[[], None]:
    key, token = _key(root), uuid4().hex
    with _LOCK:
        changing = _CHANGING.get(key)
        if changing is not None:
            description = changing[1]
            if description == 'network policy':
                raise RuntimeError('The workspace network policy is being changed. Wait for that operation to finish before starting work.')
            raise RuntimeError(f'The workspace environment is being changed ({description}). Wait for that operation to finish before starting work.')
        _ACTIVE.setdefault(key, {})[token] = label
    def release() -> None:
        with _LOCK:
            rows = _ACTIVE.get(key, {})
            rows.pop(token, None)
            if not rows:
                _ACTIVE.pop(key, None)
    return release


@contextmanager
def activity(root, label: str):
    release = acquire_activity(root, label)
    try:
        yield
    finally:
        release()


def reserve_environment_change(root, description: str = 'environment') -> Callable[[], None]:
    key, token = _key(root), uuid4().hex
    description = str(description or 'environment').strip() or 'environment'
    with _LOCK:
        current = _CHANGING.get(key)
        if current is not None:
            if current[1] == 'network policy':
                raise RuntimeError('A network-policy change is already in progress.')
            raise RuntimeError(f'A workspace environment change is already in progress ({current[1]}).')
        labels = active_work(root)
        if labels:
            if description == 'network policy':
                raise RuntimeError('Cannot change network policy while workspace work is active: ' +
                                   ', '.join(labels[:4]) + '. Stop or finish that work first; nothing was interrupted.')
            raise RuntimeError('Cannot change ' + description + ' while workspace work is active: ' +
                               ', '.join(labels[:4]) + '. Stop or finish that work first; nothing was interrupted.')
        _CHANGING[key] = (token, description)
    def release() -> None:
        with _LOCK:
            current = _CHANGING.get(key)
            if current is not None and current[0] == token:
                _CHANGING.pop(key, None)
    return release


def reserve_policy_change(root) -> Callable[[], None]:
    return reserve_environment_change(root, 'network policy')
