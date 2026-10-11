"""Origin tracking for confirmed memory writes; independent of model prompts."""
from __future__ import annotations
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from threading import RLock
from typing import Any

_ORIGIN: ContextVar[dict[str, Any] | None] = ContextVar('harnessy_memory_origin', default=None)
_LOCKS: dict[str, RLock] = {}
_LOCKS_GUARD = RLock()


def memory_lock(root: Path) -> RLock:
    key = str(root.resolve())
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(key, RLock())


@contextmanager
def memory_origin(root: Path, *, chat_id: str = '', run_id: str = '',
                  tool: str = '', tool_call_id: str = '', kind: str = 'model'):
    scope = {'root': str(root.resolve()), 'chat_id': chat_id, 'run_id': run_id,
             'tool': tool, 'tool_call_id': tool_call_id, 'kind': kind, 'events': []}
    token = _ORIGIN.set(scope)
    try:
        yield scope
    finally:
        _ORIGIN.reset(token)


def current_origin(root: Path) -> dict[str, Any] | None:
    origin = _ORIGIN.get()
    return origin if origin and origin['root'] == str(root.resolve()) else None
